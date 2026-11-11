// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"
)

// hostileRules is the number of broad security rules of hostileSnapshot.
const hostileRules = 300

// hostileSnapshot is the worst case of the per-query matching work: every
// path but the direct one is a reverse-NAT path whose pre-NAT destination
// set has MaxExpandedRangesPerField ranges (63 port forwards to dmzHost),
// and every security rule matches the zones and compares its own
// destination field of MaxExpandedRangesPerField ranges against that set,
// then fails on the service, so evaluation continues to the next rule.
func hostileSnapshot() *Snapshot {
	s := labSnapshot()
	half := MaxExpandedRangesPerField / 2
	var a, b []string
	for i := range MaxExpandedRangesPerField {
		// Every other address, so no two ranges merge.
		m := fmt.Sprintf("172.16.%d.%d", 2*i/256, 2*i%256)
		if i < half {
			a = append(a, m)
		} else {
			b = append(b, m)
		}
	}
	s.AddressGroups = append(s.AddressGroups,
		Group{Name: "many-a", Static: a}, Group{Name: "many-b", Static: b},
		Group{Name: "many", Static: []string{"many-a", "many-b"}})
	s.NATRules = forwards(MaxPathsPerQuery - 1)
	for i := range s.NATRules {
		s.NATRules[i].Destination = list("many")
	}
	s.SecurityRules = nil
	for i := range hostileRules {
		s.SecurityRules = append(s.SecurityRules, evaluableRule(fmt.Sprintf("broad-%d", i), ActionAllow,
			[]string{"any"}, []string{"any"}, []string{"any"}, []string{"many"}, []string{"svc-dns"}))
	}
	return s
}

// TestHostileQueryEndsWithinWorkBudget: one query from a hostile snapshot
// would cost far more than MaxWorkPerQuery; it stops within the budget
// with unknown "limit reached", and a job deadline stops it as well when
// the budget is lifted.
func TestHostileQueryEndsWithinWorkBudget(t *testing.T) {
	x := mustIndex(t, hostileSnapshot())
	for i := range x.rules {
		if !x.rules[i].Evaluable() {
			t.Fatalf("rule %s unevaluable: %s", x.rules[i].Name, x.rules[i].Reason())
		}
	}
	for i := range x.nat {
		if !x.nat[i].Evaluable() || len(x.natAddrs[i].dst.m) != MaxExpandedRangesPerField {
			t.Fatalf("NAT rule %s: evaluable %v, %d pre-NAT ranges", x.nat[i].Name, x.nat[i].Evaluable(), len(x.natAddrs[i].dst.m))
		}
	}
	perRule := x.ruleAddrs[0].dst.cost(x.natAddrs[0].dst.m)
	unbounded := (MaxPathsPerQuery - 1) * hostileRules * perRule
	if unbounded < 10*MaxWorkPerQuery {
		t.Fatalf("snapshot not hostile: about %d units, budget %d", unbounded, MaxWorkPerQuery)
	}
	q := internetQuery(dmzHost, 8443)

	t.Run("budget", func(t *testing.T) {
		start := time.Now()
		e := x.newEvaluator(t.Context(), q, defaultEvalLimits())
		r := e.result()
		took := time.Since(start)
		wantVerdict(t, r, VerdictUnknown, ErrLimitReached.Error())
		if r.Reason != ErrLimitReached.Error() || e.stop != ErrLimitReached.Error() {
			t.Fatalf("reason %q, stop %q", r.Reason, e.stop)
		}
		if e.work > MaxWorkPerQuery || e.work < MaxWorkPerQuery-perRule {
			t.Fatalf("work %d, want the budget %d spent and not exceeded", e.work, MaxWorkPerQuery)
		}
		if last := r.Chain[len(r.Chain)-1]; last.Kind != StepVerdict {
			t.Fatalf("chain ends with %+v", last)
		}
		if took > JobBudget {
			t.Fatalf("query took %v, job budget %v", took, JobBudget)
		}
		t.Logf("work %d of %d (unbounded about %d) in %v", e.work, MaxWorkPerQuery, unbounded, took)
	})

	t.Run("deadline", func(t *testing.T) {
		lim := defaultEvalLimits()
		lim.work = math.MaxInt
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		start := time.Now()
		e := x.newEvaluator(ctx, q, lim)
		r := e.result()
		took := time.Since(start)
		wantVerdict(t, r, VerdictUnknown, ReasonDeadline)
		if r.Reason != ReasonDeadline {
			t.Fatalf("reason %q", r.Reason)
		}
		// One rule step is the largest unit between two deadline checks.
		if took > 10*time.Second {
			t.Fatalf("query stopped %v after start, deadline 50ms", took)
		}
	})
}

// TestWorkBudgetBoundary: a query that needs exactly the budget gives the
// same result as without a limit; one unit less gives unknown "limit
// reached".
func TestWorkBudgetBoundary(t *testing.T) {
	s := labSnapshot()
	s.NATRules = forwards(5)
	x := mustIndex(t, s)
	for _, q := range []Query{internetQuery(wanAddr, 443), internetQuery(dmzHost, 8443), addrQuery(lanHost, "192.168.99.1", 22)} {
		e := x.newEvaluator(t.Context(), q, defaultEvalLimits())
		full := e.result()
		if e.stop != "" || full.Verdict == VerdictUnknown {
			t.Fatalf("%v: unlimited run %s %q", q, full.Verdict, full.Reason)
		}
		lim := defaultEvalLimits()
		lim.work = e.work
		if at := x.evaluate(t.Context(), q, lim); !reflect.DeepEqual(at, full) {
			t.Fatalf("%v at budget %d:\n%s", q, e.work, at.Text())
		}
		lim.work = e.work - 1
		over := x.evaluate(t.Context(), q, lim)
		wantVerdict(t, over, VerdictUnknown, ErrLimitReached.Error())
		if over.Reason != ErrLimitReached.Error() {
			t.Fatalf("%v over budget: reason %q", q, over.Reason)
		}
	}
	if MaxWorkPerQuery <= 0 {
		t.Fatal("no work budget")
	}
}

// TestNATLoopsStopWhenChainFills: when the chain fills in the middle of
// the forward NAT loop or the reverse-NAT loop, the loop stops at the next
// NAT rule instead of matching every remaining one.
func TestNATLoopsStopWhenChainFills(t *testing.T) {
	const n = 1000
	cases := []struct {
		name          string
		q             Query
		mod           func(*NATRule)
		kind          StepKind
		maxPercent    int // of the unlimited work, after the chain filled
		budgetPercent int // of the unlimited work, runs out in the loop
	}{
		// No NAT rule matches the service: one forward step per rule.
		{"forward", internetQuery(wanAddr, 443), func(r *NATRule) { r.Service = Collected("svc-dns") }, StepNAT, 5, 20},
		// Every rule forwards to the destination from another zone: one
		// forward and one reverse-NAT step per rule.
		{"reverse", internetQuery(dmzHost, 8443), func(r *NATRule) { r.From = list("lan") }, StepReverseNAT, 55, 75},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := labSnapshot()
			s.NATRules = forwards(n)
			for i := range s.NATRules {
				c.mod(&s.NATRules[i])
			}
			x := mustIndex(t, s)
			all := x.newEvaluator(t.Context(), c.q, defaultEvalLimits())
			full := all.result()
			first, steps := -1, 0
			for i, st := range full.Chain {
				if st.Kind == c.kind {
					steps++
					if first < 0 {
						first = i
					}
				}
			}
			if all.stop != "" || steps != n {
				t.Fatalf("unlimited run: stop %q, %d %s steps, want %d\n", all.stop, steps, c.kind, n)
			}
			// The chain fills ten rules into the loop.
			lim := defaultEvalLimits()
			lim.steps = first + 10
			e := x.newEvaluator(t.Context(), c.q, lim)
			r := e.result()
			wantVerdict(t, r, VerdictUnknown, ErrLimitReached.Error())
			if e.stop != ErrLimitReached.Error() {
				t.Fatalf("stop %q", e.stop)
			}
			// Every NAT rule costs about the same, so the work done is the
			// share of the NAT rules visited: about 10 of n in the forward
			// case, n forward plus about 10 reverse of 2n in the reverse
			// case.
			if e.work*100 > all.work*c.maxPercent {
				t.Fatalf("after the chain filled: %d of %d units; loop did not stop", e.work, all.work)
			}
			// The same check stops the loop when the budget runs out in it;
			// the chain then shows that the remaining rules were not visited.
			lim = defaultEvalLimits()
			lim.work = all.work * c.budgetPercent / 100
			r = x.evaluate(t.Context(), c.q, lim)
			wantVerdict(t, r, VerdictUnknown, ErrLimitReached.Error())
			visited := 0
			for _, st := range r.Chain {
				if st.Kind == c.kind {
					visited++
				}
			}
			if visited == 0 || visited > n*9/10 {
				t.Fatalf("budget ran out in the loop: %d of %d %s steps", visited, n, c.kind)
			}
		})
	}
}

// countdownCtx reports its deadline exceeded after n calls of Err.
type countdownCtx struct {
	context.Context
	n int
}

func (c *countdownCtx) Err() error {
	if c.n <= 0 {
		return context.DeadlineExceeded
	}
	c.n--
	return nil
}

// TestEvaluateStopsAtDeadline: a context that is done before or during
// the query stops it with unknown "deadline" or "canceled"; the chain still
// ends with the verdict.
func TestEvaluateStopsAtDeadline(t *testing.T) {
	s := labSnapshot()
	s.NATRules = forwards(20)
	x := mustIndex(t, s)
	q := internetQuery(dmzHost, 8443)
	wantVerdict(t, x.Evaluate(t.Context(), q), VerdictAllowed, "allow-web")

	expired, cancel := context.WithDeadline(t.Context(), time.Unix(0, 0))
	defer cancel()
	r := x.Evaluate(expired, q)
	wantVerdict(t, r, VerdictUnknown, ReasonDeadline)
	if r.Reason != ReasonDeadline || len(r.Chain) != 1 || r.Chain[0].Kind != StepVerdict {
		t.Fatalf("expired context:\n%s", r.Text())
	}

	canceled, cancel2 := context.WithCancel(t.Context())
	cancel2()
	if r := x.Evaluate(canceled, q); r.Verdict != VerdictUnknown || r.Reason != ReasonCanceled {
		t.Fatalf("canceled context: %s %q", r.Verdict, r.Reason)
	}

	// Count the checks of a full run, then let the deadline pass halfway.
	count := &countdownCtx{Context: t.Context(), n: math.MaxInt}
	x.Evaluate(count, q)
	checks := math.MaxInt - count.n
	if checks < 40 {
		t.Fatalf("only %d deadline checks in a query with 21 paths", checks)
	}
	e := x.newEvaluator(&countdownCtx{Context: t.Context(), n: checks / 2}, q, defaultEvalLimits())
	r = e.result()
	wantVerdict(t, r, VerdictUnknown, ReasonDeadline)
	if r.Reason != ReasonDeadline || e.stop != ReasonDeadline {
		t.Fatalf("mid-query deadline: reason %q, stop %q", r.Reason, e.stop)
	}
	if last := r.Chain[len(r.Chain)-1]; last.Kind != StepVerdict || last.Detail != ReasonDeadline {
		t.Fatalf("chain ends with %+v", last)
	}
	if e.paths == 0 || e.paths >= 21 {
		t.Fatalf("stopped after %d paths, want part of the 21", e.paths)
	}
}

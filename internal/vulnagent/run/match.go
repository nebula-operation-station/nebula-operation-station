// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"context"
	"fmt"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnmatch"
)

// prepared is one finding ready to be assessed and sent.
type prepared struct {
	rec vulnfinding.Record
	key string
	// subject is the subject key (nosclient snapshot key form).
	subject string
}

// matched is the outcome of run order phase 3.
type matched struct {
	findings []prepared
	// uncovered holds the subjects the run must not name as covered: a
	// coverage gap or a withheld finding means the run did not see the
	// subject completely, so NOS must not close anything on it.
	uncovered map[string]bool
	loaded    []loadedFeed
	sources   []RunSource
	snap      *snapshotView
	view      *runView
	version   string
}

func subjectKey(kind vulnfinding.SubjectKind, ref vulnfinding.SubjectRef) string {
	return string(kind) + "|" + ref.ID + "|" + ref.ImageDigest
}

// match is run order phase 3: load the pinned snapshots and match the
// export against them.
func (r *Runner) match(ctx context.Context, parts []nosclient.SubjectPart, rep *Report) (*matched, error) {
	subjects, err := vulnmatch.SubjectsFromExport(parts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMatch, err)
	}
	wanted := map[string]bool{}
	for _, s := range subjects {
		if rel, ok := strings.CutPrefix(s.Ecosystem, "debian:"); ok {
			for _, c := range s.Components {
				wanted[rel+"/"+c.SourcePackage] = true
			}
			if s.Kernel != nil && s.Kernel.Mapped {
				wanted[rel+"/"+s.Kernel.SourcePackage] = true
			}
		}
	}
	snap := newSnapshotView(wanted)
	db, loaded, err := r.loadDB(ctx, snap, rep)
	if err != nil {
		return nil, err
	}
	if len(loaded) == 0 {
		return nil, ErrNoFeeds
	}
	res, err := vulnmatch.Match(db, subjects, vulnmatch.Options{})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMatch, err)
	}
	m := &matched{uncovered: map[string]bool{}, loaded: loaded, sources: runSources(loaded), snap: snap,
		view: &runView{backport: map[string]agent.Backport{}, exposure: map[string]agent.Exposure{}}, version: res.MatcherVersion}
	rep.RunSources, rep.MatcherVersion = m.sources, res.MatcherVersion
	for _, g := range res.Gaps {
		m.uncovered[subjectKey(g.Kind, g.Ref)] = true
	}
	for _, w := range res.Withheld {
		m.uncovered[subjectKey(w.Kind, w.Ref)] = true
		r.log.Warn("finding withheld: record over bounds", "subject_kind", string(w.Kind), "subject", w.Ref.ID,
			"vuln_id", w.VulnID, "reason", cleanText(w.Err.Error(), maxEvidenceText))
	}
	rep.Gaps, rep.Withheld, rep.FeedPartsCut = len(res.Gaps), len(res.Withheld), res.FeedPartsCut
	kernels := map[string]*vulnmatch.Kernel{}
	for _, s := range subjects {
		kernels[subjectKey(s.Kind, s.Ref)] = s.Kernel
	}
	for _, f := range res.Findings {
		vf, err := vulnfinding.Validate(f.Record)
		if err != nil {
			// The matcher validates every record; this is a fail-safe.
			rep.Withheld++
			sk := subjectKey(f.Record.SubjectKind, f.Record.SubjectRef)
			m.uncovered[sk] = true
			r.log.Warn("finding withheld: record invalid", "subject", f.Record.SubjectRef.ID, "vuln_id", f.Record.Vuln.ID)
			continue
		}
		p := prepared{rec: vf.Record, key: vf.Key.String(), subject: subjectKey(vf.Record.SubjectKind, vf.Record.SubjectRef)}
		m.findings = append(m.findings, p)
		m.view.backport[p.key] = agent.Backport{BasisVersion: p.rec.Component.SourceVersion, FixedVersion: p.rec.Fix.Version,
			Verdict: "affected", TrackerNote: vf.TrackerNote}
		e := agent.Exposure{SubjectKind: string(p.rec.SubjectKind), Ecosystem: p.rec.Ecosystem}
		for _, b := range p.rec.Component.Binaries {
			e.BinaryPackages = append(e.BinaryPackages, b.Name)
		}
		if k := kernels[p.subject]; k != nil && k.Mapped && k.SourcePackage == p.rec.Component.SourcePackage {
			e.Kernel = "running"
		}
		m.view.exposure[p.key] = e
	}
	rep.Findings = len(m.findings)
	r.log.Info("matched", "subjects", len(subjects), "findings", len(m.findings), "gaps", len(res.Gaps),
		"withheld", rep.Withheld, "feed_parts_cut", res.FeedPartsCut, "matcher_version", res.MatcherVersion)
	return m, nil
}

// facts returns the bounded facts the assessor sees for p.
func facts(p prepared) agent.FindingFacts {
	f := agent.FindingFacts{FindingKey: p.key, VulnID: p.rec.Vuln.ID, Aliases: p.rec.Vuln.Aliases,
		SubjectKind: string(p.rec.SubjectKind), Ecosystem: p.rec.Ecosystem,
		SourcePackage: p.rec.Component.SourcePackage, SourceVersion: p.rec.Component.SourceVersion,
		KEV: p.rec.Scores.KEV != nil}
	if f.SourcePackage == "" {
		f.SourcePackage, f.SourceVersion = p.rec.Component.Model, p.rec.Component.Firmware
	}
	if p.rec.Fix.State == vulnfinding.FixFixed {
		f.FixedVersion = p.rec.Fix.Version
	} else {
		f.Fix = string(p.rec.Fix.State)
	}
	if c := p.rec.Scores.CVSS; c != nil {
		s := c.BaseScore
		f.CVSSMax = &s
	}
	if e := p.rec.Scores.EPSS; e != nil {
		pr := e.Probability
		f.EPSS = &pr
	}
	return f
}

// assess is run order phase 4. It never fails the run: every limit,
// endpoint error or refused setting leaves the findings without text.
func (r *Runner) assess(ctx context.Context, m *matched, rep *Report) {
	eff, ev := r.resolveLLM(ctx)
	rep.LLM = ev
	if !eff.Enabled || len(m.findings) == 0 {
		r.log.Info("assessment skipped", "enabled", eff.Enabled, "reason", ev.Reason, "findings", len(m.findings))
		return
	}
	a, err := r.newAssessor(eff, m)
	if err != nil {
		rep.LLM.Enabled = false
		rep.LLM.Reason = cleanText(err.Error(), maxEvidenceText)
		r.log.Warn("assessor not started, findings sent without text", "error", rep.LLM.Reason)
		return
	}
	fs := make([]agent.FindingFacts, len(m.findings))
	idx := make(map[string]int, len(m.findings))
	for i, p := range m.findings {
		fs[i] = facts(p)
		idx[p.key] = i
	}
	pctx, cancel := context.WithTimeout(ctx, r.cfg.AssessPhaseMax)
	defer cancel()
	ar := a.Run(pctx, fs)
	rep.LLM.Calls, rep.LLM.Tokens = ar.Calls, ar.TokensCharged
	for _, res := range ar.Results {
		if res.Outcome != agent.OutcomeAssessed || res.Assessment == nil {
			continue
		}
		i, ok := idx[res.FindingKey]
		if !ok {
			continue
		}
		as := res.Assessment
		cand := m.findings[i].rec
		cand.Assessment = vulnfinding.Assessment{Text: as.Text, BackportChecked: as.BackportChecked,
			LikelyFalsePositive: as.LikelyFalsePositive, ExploitPublic: as.ExploitPublic}
		// The record must stay valid with the text; otherwise it is sent
		// without it.
		if _, err := vulnfinding.Validate(cand); err != nil {
			r.log.Warn("assessment dropped: record invalid with text", "finding_key", res.FindingKey)
			continue
		}
		m.findings[i].rec = cand
		rep.LLM.Assessed++
	}
	r.log.Info("assessment finished", "assessed", rep.LLM.Assessed, "findings", len(m.findings),
		"calls", ar.Calls, "tokens", ar.TokensCharged, "budget_exhausted", ar.BudgetExhausted)
}

// newAssessor builds the LLM client and the agent for the effective
// settings.
func (r *Runner) newAssessor(eff LLMConfig, m *matched) (*agent.Agent, error) {
	newLLM := r.cfg.NewLLM
	if newLLM == nil {
		newLLM = func(c agent.ClientConfig) (agent.LLM, error) { return agent.NewHTTPClient(c) }
	}
	llm, err := newLLM(agent.ClientConfig{BaseURL: eff.BaseURL, Model: eff.Model, APIKeyFile: eff.APIKeyFile,
		AllowPlainHTTP: eff.AllowPlainHTTP, Timeout: eff.Limits.LLMCallTimeout})
	if err != nil {
		return nil, fmt.Errorf("llm client: %w", err)
	}
	prompt, err := agent.NewPrompt(eff.OperatorInstructions, eff.Language)
	if err != nil {
		return nil, fmt.Errorf("prompt: %w", err)
	}
	a, err := agent.New(agent.Config{Enabled: true, LLM: llm, Prompt: prompt, Limits: eff.Limits,
		Snapshot: m.snap, View: m.view, Logger: r.log})
	if err != nil {
		return nil, fmt.Errorf("assessor: %w", err)
	}
	return a, nil
}

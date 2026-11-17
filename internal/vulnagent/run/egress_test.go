// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/llmclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
)

// The dialer's own rules are tested in internal/llmclient. These tests cover
// what the run adds: the refusal reaches the report without text, the
// client is always built with the lab-only options, and configuration errors
// keep this package's sentinel.

func assertSentWithoutText(t *testing.T, e *env, rep *Report) {
	t.Helper()
	if rep.LLM.Assessed != 0 {
		t.Errorf("assessed = %d", rep.LLM.Assessed)
	}
	recs := e.nos.sentRecords(t)
	if len(recs) != 1 || recs[0].Assessment.Text != "" {
		t.Errorf("finding not sent without text: %+v", recs)
	}
	e.assertNoSecrets(t)
}

func TestRefusedLLMEndpointSendsFindingsWithoutText(t *testing.T) {
	e := newEnv(t)
	e.nos.setLLM(true, "https://203.0.113.7/v1", "nos-model")
	rep, err := e.runner(t).Run(context.Background(), ModeRun)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if e.llm.callCount() != 0 {
		t.Errorf("llm called %d times", e.llm.callCount())
	}
	if rep.LLM.Enabled || !rep.LLM.Failed || !strings.Contains(rep.LLM.Reason, "vulnagent/run: llm endpoint is not a lab address") {
		t.Errorf("llm evidence = %+v", rep.LLM)
	}
	if !rep.Degraded() {
		t.Error("refused endpoint did not degrade the run")
	}
	assertSentWithoutText(t, e, rep)
}

func TestLLMClientIsAlwaysLabOnly(t *testing.T) {
	e := newEnv(t)
	e.nos.setLLM(true, e.llm.srv.URL+"/v1", "nos-model")
	var got []llmclient.Options
	rep, err := e.runner(t, func(c *Config) {
		c.NewLLM = func(o llmclient.Options) (agent.LLM, error) {
			got = append(got, o)
			return agent.NewLLM(o)
		}
	}).Run(context.Background(), ModeRun)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !rep.LLM.Enabled || rep.LLM.Failed || rep.LLM.Assessed != 1 {
		t.Fatalf("llm evidence = %+v", rep.LLM)
	}
	if len(got) != 1 {
		t.Fatalf("client built %d times", len(got))
	}
	if !got[0].LabOnly || got[0].UnixSocket != "" || got[0].BaseURL != e.llm.srv.URL+"/v1" {
		t.Errorf("client options = %+v", got[0])
	}
	e.assertNoSecrets(t)
}

func TestLLMClientOptionsCarryConfiguredNetworks(t *testing.T) {
	e := newEnv(t)
	e.nos.setLLM(true, e.llm.srv.URL+"/v1", "nos-model")
	var got llmclient.Options
	_, err := e.runner(t, func(c *Config) {
		c.LLM.AllowedNetworks = []string{"100.64.0.0/16"}
		c.NewLLM = func(o llmclient.Options) (agent.LLM, error) {
			got = o
			return agent.NewLLM(o)
		}
	}).Run(context.Background(), ModeRun)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(got.LabNetworks) != 1 || got.LabNetworks[0].String() != "100.64.0.0/16" {
		t.Errorf("lab networks = %v", got.LabNetworks)
	}
}

func TestAllowedNetworksRefusedAsConfig(t *testing.T) {
	for name, nets := range map[string][]string{
		"allowed network outside ranges": {"203.0.113.0/24"},
		"allowed network too wide":       {"10.0.0.0/7"},
		"allowed network nat64":          {"64:ff9b::/96"},
		"allowed network inside nat64":   {"64:ff9b::a00:0/120"},
		"allowed network mapped":         {"::ffff:10.0.0.0/104"},
		"allowed network not a prefix":   {"10.0.0.1"},
		"too many networks":              make([]string, llmclient.MaxNetworks+1),
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			cfg := e.config(t)
			cfg.LLM.AllowedNetworks = nets
			_, err := New(cfg)
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("New = %v, want ErrConfig", err)
			}
			if !strings.Contains(err.Error(), "llm allowed networks: ") || !strings.HasSuffix(err.Error(), ": vulnagent/run: invalid configuration") {
				t.Errorf("message %q", err)
			}
			if e.llm.callCount() != 0 || e.nos.postCount() != 0 {
				t.Error("request left with a refused configuration")
			}
		})
	}
}

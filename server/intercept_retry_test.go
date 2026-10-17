package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iooxxh/artex/db"
	"github.com/iooxxh/artex/intercept"
)

func TestJudgeRetrySettingsAndFallbackHTTP(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("no test database configured")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	i := intercept.New(d)
	before := i.GetJudgeConfig()
	t.Cleanup(func() {
		if err := i.SetJudgeConfig(before); err != nil {
			t.Error(err)
		}
	})
	s := &Server{m: &Manager{pg: d, interceptor: i}, jwtKey: []byte("judge-retry-test-key")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	do := func(method string, cfg intercept.JudgeConfig) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, "/api/intercept/judge", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	cfg := before
	cfg.Enabled, cfg.FailAction = true, "ask"
	cfg.RetryCount, cfg.RetryIntervalMS = 2, 0
	if rec := do(http.MethodPut, cfg); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	for _, invalid := range []intercept.JudgeConfig{
		{RetryCount: -1}, {RetryCount: 11}, {RetryIntervalMS: -1}, {RetryIntervalMS: 60_001},
	} {
		if rec := do(http.MethodPut, invalid); rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid settings: %d %s", rec.Code, rec.Body.String())
		}
	}
	var loaded intercept.JudgeConfig
	rec := do(http.MethodGet, cfg)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &loaded) != nil || loaded.RetryCount != 2 || loaded.RetryIntervalMS != 0 || !loaded.Enabled {
		t.Fatalf("settings changed after failed save: %d %s", rec.Code, rec.Body.String())
	}
	if reloaded := intercept.New(d).GetJudgeConfig(); reloaded.RetryCount != 2 || reloaded.FailAction != "ask" {
		t.Fatalf("retry settings not persisted: %+v", reloaded)
	}
	calls := 0
	i.SetReviewer(func(context.Context, int64, string, intercept.ReviewInput) (intercept.Decision, error) {
		calls++
		return intercept.Decision{}, errors.New("temporary provider failure")
	})
	out, handled := i.Judge(t.Context(), "Bash", json.RawMessage(`{"command":"pwd"}`))
	if !handled || calls != 3 || out.Action != "ask" || !out.ModelFallback || !out.TimeoutEnabled || !strings.Contains(out.Message, "3 次") {
		t.Fatalf("retry exhaustion lost fail policy: calls=%d out=%+v", calls, out)
	}
	calls = 0
	out, handled = i.Judge(t.Context(), "Bash", json.RawMessage(`{"broken"`))
	if !handled || calls != 0 || out.Action != "ask" {
		t.Fatalf("invalid review input was sent to model: calls=%d out=%+v", calls, out)
	}
	cfg.FailAction = "allow"
	if rec := do(http.MethodPut, cfg); rec.Code != http.StatusOK {
		t.Fatalf("save fail-open policy: %d", rec.Code)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out, handled = i.Judge(ctx, "Bash", json.RawMessage(`{"command":"pwd"}`))
	if !handled || calls != 0 || out.Action != "deny" || !strings.Contains(out.Message, "审核已取消") {
		t.Fatalf("cancellation was treated as fail-open approval: calls=%d out=%+v", calls, out)
	}
}

package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// getAPIToken returns the configured token to an authenticated caller (the panel's view).
func TestGetAPIToken(t *testing.T) {
	a := &api{cfg: Config{APIToken: "secrettoken123"}}
	rec := httptest.NewRecorder()
	a.getAPIToken(rec, httptest.NewRequest("GET", "/api-token", nil))
	if rec.Code != 200 {
		t.Fatalf("code=%d want 200", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if resp["token"] != "secrettoken123" {
		t.Errorf("token=%v want secrettoken123", resp["token"])
	}
}

func TestAPITokenAccessor(t *testing.T) {
	a := &api{cfg: Config{APIToken: "abc"}}
	if got := a.apiToken(); got != "abc" {
		t.Errorf("apiToken()=%q want %q", got, "abc")
	}
}

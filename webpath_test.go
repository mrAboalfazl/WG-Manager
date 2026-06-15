package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormBase(t *testing.T) {
	cases := map[string]string{
		"":         "",
		"/":        "",
		"///":      "",
		"abc":      "/abc",
		"/abc":     "/abc",
		"/abc/":    "/abc",
		"  /abc/ ": "/abc",
	}
	for in, want := range cases {
		if got := normBase(in); got != want {
			t.Errorf("normBase(%q)=%q want %q", in, got, want)
		}
	}
}

// serveUI must replace the __WGMGR_BASE__ placeholder with the configured base so the
// SPA's fetch() calls hit /<base>/... — and an empty base must leave it serving at root.
func TestServeUIInjectsBase(t *testing.T) {
	for _, bp := range []string{"", "/a1b2c3"} {
		a := &api{cfg: Config{BasePath: bp}}
		rec := httptest.NewRecorder()
		a.serveUI(rec, httptest.NewRequest("GET", "/", nil))
		body := rec.Body.String()
		if strings.Contains(body, "__WGMGR_BASE__") {
			t.Errorf("bp=%q: placeholder was not replaced", bp)
		}
		if want := `const BASE="` + bp + `";`; !strings.Contains(body, want) {
			t.Errorf("bp=%q: body missing %q", bp, want)
		}
	}
}

// TestBasePathRouting validates the exact StripPrefix mounting that startAPI uses:
// routes are reachable under /<base>/ and the bare root is dark (404).
func TestBasePathRouting(t *testing.T) {
	inner := http.NewServeMux()
	inner.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	inner.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ui") })

	bp := normBase("/a1b2c3")
	outer := http.NewServeMux()
	outer.Handle(bp+"/", http.StripPrefix(bp, inner))

	srv := httptest.NewServer(outer)
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	check := func(path string, wantCode int, wantBody string) {
		t.Helper()
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != wantCode {
			t.Errorf("GET %s: code=%d want %d", path, resp.StatusCode, wantCode)
		}
		if wantBody != "" && strings.TrimSpace(string(b)) != wantBody {
			t.Errorf("GET %s: body=%q want %q", path, strings.TrimSpace(string(b)), wantBody)
		}
	}
	check("/a1b2c3/healthz", 200, "ok")  // API route reachable under the base
	check("/a1b2c3/", 200, "ui")         // base root serves the SPA
	check("/a1b2c3/anything", 200, "ui") // SPA fallback under the base
	check("/healthz", 404, "")           // bare root is dark
	check("/", 404, "")                  // bare root is dark

	// /a1b2c3 (no trailing slash) must redirect to /a1b2c3/
	resp, err := client.Get(srv.URL + "/a1b2c3")
	if err != nil {
		t.Fatalf("GET /a1b2c3: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		t.Errorf("GET /a1b2c3: code=%d want a redirect", resp.StatusCode)
	}
}

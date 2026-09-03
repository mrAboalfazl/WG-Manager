package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// versionCache memoizes the GitHub "latest release" answer so a rapid
// Check-for-updates click (or a slow render loop) can't hammer GitHub's
// 60/hr unauthenticated rate limit. Refreshed at most once per ttl.
type versionCache struct {
	mu       sync.Mutex
	fetched  time.Time
	ttl      time.Duration
	payload  latestRelease
	fetchErr error
}

type latestRelease struct {
	Tag         string `json:"tag_name"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
}

var ghLatestCache = &versionCache{ttl: 5 * time.Minute}

// fetchLatestRelease returns the freshest cached copy, refreshing only when the
// cached entry is older than ttl OR the previous attempt failed. On error it
// returns the last-known-good payload (which may be zero) plus the error so the
// handler can still show the installed version when GitHub is unreachable.
func (c *versionCache) fetchLatestRelease(ctx httpCtx) (latestRelease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	// Serve fresh cache (only when the last fetch succeeded — a cached error re-fetches).
	if !c.fetched.IsZero() && c.fetchErr == nil && now.Sub(c.fetched) < c.ttl {
		return c.payload, nil
	}
	req, err := http.NewRequestWithContext(ctx.ctx(), "GET",
		"https://api.github.com/repos/mrAboalfazl/WG-Manager/releases/latest", nil)
	if err != nil {
		c.fetchErr = err
		return c.payload, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wgmgr-panel/"+Version)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.fetchErr = err
		return c.payload, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		c.fetchErr = fmt.Errorf("github: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		return c.payload, c.fetchErr
	}
	var rel latestRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&rel); err != nil {
		c.fetchErr = err
		return c.payload, err
	}
	c.payload = rel
	c.fetched = now
	c.fetchErr = nil
	return rel, nil
}

// httpCtx is a tiny wrapper so callers that only have a plain background need can pass one.
type httpCtx struct{ r *http.Request }

func (c httpCtx) ctx() context.Context { return c.r.Context() }

// isNewer reports whether latest > installed under semver-ish rules. Only tags of the
// form vN[.N[.N]] are compared numerically; anything else falls back to string inequality.
// "dev" or "source-*" installed values are treated as "always older" so a dev build sees
// an upgrade prompt if a release exists — the operator can then get onto a proper release.
func isNewer(latest, installed string) bool {
	if latest == "" || installed == "" || latest == installed {
		return false
	}
	if installed == "dev" || strings.HasPrefix(installed, "source-") {
		return true
	}
	li, ok1 := semParts(latest)
	ii, ok2 := semParts(installed)
	if !ok1 || !ok2 {
		return latest != installed // best-effort
	}
	for k := 0; k < 3; k++ {
		if li[k] != ii[k] {
			return li[k] > ii[k]
		}
	}
	return false
}

// semParts turns "v1.6.10" into [1,6,10]. Missing minor/patch default to 0. Anything
// unparseable returns ok=false and the caller falls back to string comparison.
func semParts(s string) ([3]int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	f := strings.SplitN(s, ".", 3)
	var out [3]int
	for i, p := range f {
		// strip any trailing prerelease/build suffix like "-rc1" or "+meta"
		if j := strings.IndexAny(p, "-+"); j >= 0 {
			p = p[:j]
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// versionH backs `GET /version`. Returns the installed Version plus GitHub's latest
// release info when reachable. If GitHub can't be reached the response still carries
// the installed version so the panel Update card can render — with a soft "check
// failed" note — instead of erroring out.
func (a *api) versionH(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"installed": Version,
	}
	rel, err := ghLatestCache.fetchLatestRelease(httpCtx{r: r})
	if err != nil {
		resp["latest"] = nil
		resp["update_available"] = false
		resp["check_error"] = err.Error()
		writeJSON(w, 200, resp)
		return
	}
	resp["latest"] = rel.Tag
	resp["update_available"] = isNewer(rel.Tag, Version)
	resp["published_at"] = rel.PublishedAt
	resp["release_url"] = rel.HTMLURL
	// Truncate release notes to keep the response light — the full text lives at release_url.
	notes := rel.Body
	if len(notes) > 2000 {
		notes = notes[:2000] + "…"
	}
	resp["release_notes"] = notes
	writeJSON(w, 200, resp)
}

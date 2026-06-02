package main

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func hashPass(p string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		die("hash password: %v", err)
	}
	return string(h)
}

func checkPass(hash, p string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(p)) == nil
}

// login validates admin username/password and returns the API token for the SPA to use.
// Public endpoint (no bearer needed) — that's how a human obtains the token. Admin
// credentials are set at install: `wgmgr init` generates a random password (printed once);
// change anytime with `wgmgr set-login <user> <pass>`.
func (a *api) login(w http.ResponseWriter, r *http.Request) {
	m := readJSON(r)
	u, _ := m["username"].(string)
	p, _ := m["password"].(string)
	user := a.cfg.AdminUser
	if user == "" {
		user = "admin"
	}
	ok := false
	if a.cfg.AdminPassHash != "" {
		ok = u == user && checkPass(a.cfg.AdminPassHash, p)
	}
	if !ok {
		writeJSON(w, 401, map[string]any{"error": "invalid username or password"})
		return
	}
	writeJSON(w, 200, map[string]any{"token": a.cfg.APIToken})
}

package main

import (
	"database/sql"
	"fmt"
	"strings"
)

// ghostUsers lists user rows with neither a WireGuard nor an OpenVPN identity. Before
// v1.8 an OVPN-only add that failed with "no free IP" (full /24) left such a row behind;
// a user whose only OVPN identity was removed with `ovpn-rm` looks the same. Either way
// nobody can connect with it.
func ghostUsers(db *sql.DB) []string {
	rows, err := db.Query(`SELECT username FROM peers
		WHERE COALESCE(public_key,'')='' AND COALESCE(ovpn_cn,'')='' ORDER BY username`)
	if err != nil {
		die("query: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			die("scan: %v", err)
		}
		out = append(out, u)
	}
	return out
}

// cmdGhostUsers: wgmgr ghost-users [--delete]
func cmdGhostUsers(args []string) {
	_, flags := parseFlags(args)
	cfg := loadConfig()
	db := openDB(cfg.DB)
	defer db.Close()
	ghosts := ghostUsers(db)
	if len(ghosts) == 0 {
		fmt.Println("no ghost users (every user has a WireGuard or OpenVPN identity)")
		return
	}
	fmt.Printf("%d user(s) with no WireGuard and no OpenVPN identity: %s\n", len(ghosts), strings.Join(ghosts, ", "))
	if flags["delete"] != "true" {
		fmt.Println("delete them with: wgmgr ghost-users --delete")
		return
	}
	for _, u := range ghosts {
		if _, err := db.Exec("DELETE FROM peers WHERE username=? AND COALESCE(public_key,'')='' AND COALESCE(ovpn_cn,'')=''", u); err != nil {
			die("delete %s: %v", u, err)
		}
	}
	fmt.Printf("deleted %d ghost user(s)\n", len(ghosts))
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// A realtime key is a credential that can do exactly one thing: subscribe to
// the change feed of the one branch it names.
//
// It exists because the stream used to be reached with a branch-scoped gateway
// key, and that was defended as a strict subset — the key already opened all
// SQL on that branch as db_client, so a read-only feed of tables somebody had
// explicitly enabled widened nothing. True, and still a poor trade: an
// application that only wants to be told when a row changes had to hold a
// credential that could also read every table and drop them.
//
// So this kind removes the SQL reach rather than relying on it:
//
//	account key   key_   control plane, gateway, stream — the owner's full access
//	scoped key    key_   that branch's SQL, and its stream
//	realtime key  rtk_   that branch's stream. Nothing else.
//
// Refused at the control plane by Authn (as every scoped key already is), and
// refused at the Gateway by kind — which is the clause that makes the sentence
// above true rather than aspirational, and is asserted in both the unit tests
// and the integration suite.
const (
	// KindRealtime marks a key minted for the change feed.
	KindRealtime = "realtime"

	// RealtimeKeyPrefix begins one. Visibly different from KeyPrefix so that a
	// key found in a log, a config file or a screenshot can be told apart at a
	// glance — the question "what could this have done?" should not need a
	// database lookup. Brand-free for the same reason KeyPrefix is.
	RealtimeKeyPrefix = "rtk_"
)

// ErrRealtimeKeyNeedsBranch is returned when no branch was named. A realtime
// key with no scope would be a key to every branch's feed, which is the one
// thing this kind exists not to be, so it is refused at mint time rather than
// interpreted.
var ErrRealtimeKeyNeedsBranch = errors.New("a realtime key must name the branch it is for")

// CreateRealtimeKey mints a stream-only key for one branch and returns the
// secret, which is shown once and never stored.
func (s *Store) CreateRealtimeKey(userID int64, name, branchName string) (string, KeyInfo, error) {
	branchName = strings.TrimSpace(branchName)
	if branchName == "" {
		return "", KeyInfo{}, ErrRealtimeKeyNeedsBranch
	}
	if strings.TrimSpace(name) == "" {
		name = "realtime"
	}
	secret := RealtimeKeyPrefix + randToken(24)
	id := randToken(8)
	prefix := secret[:12]
	now := time.Now().Unix()
	if _, err := s.db.Exec(
		`INSERT INTO api_keys(id,user_id,name,key_hash,prefix,created,scope,kind) VALUES(?,?,?,?,?,?,?,?)`,
		id, userID, name, hashKey(secret), prefix, now, branchName, KindRealtime); err != nil {
		return "", KeyInfo{}, err
	}
	return secret, KeyInfo{ID: id, Name: name, Prefix: prefix, Created: now,
		Scope: branchName, Kind: KindRealtime}, nil
}

// UserForRealtime authenticates a request to the realtime front door.
//
// It accepts, in order: a console session or an unscoped account key (so the
// console's own REALTIME pages work with the cookie the operator already has),
// a realtime key scoped to this branch, or a gateway key scoped to this branch
// — the last of those only because it already worked before this kind existed,
// and removing it would break a subscriber that is running today.
//
// Everything else is not authenticated here. In particular a key scoped to
// another branch is not: a caller has to name the branch its key is for.
func (s *Store) UserForRealtime(r *http.Request, branchName string) (User, bool) {
	if u, ok := s.userFromRequest(r); ok {
		return u, true // a session, or an unscoped key: Authn's rules
	}
	key := bearerKey(r)
	if key == "" || strings.TrimSpace(branchName) == "" {
		return User{}, false
	}
	u, scope, _, ok := s.VerifyKeyKind(key)
	if !ok || scope == "" || scope != branchName {
		return User{}, false
	}
	return u, true // kind realtime or a scoped gateway key: both may stream
}

// bearerKey reads the credential out of the headers, and only out of the
// headers. Never a query parameter: a URL is written to access logs, kept in
// browser history and sent in Referer, and a key that reaches any of those has
// to be treated as disclosed. This is also why the realtime DSN carries its key
// in userinfo and the client turns it into a header.
func bearerKey(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return r.Header.Get("X-API-Key")
}

// RealtimeKeysFor lists one branch's realtime keys, without their secrets —
// those are not stored.
//
// By branch rather than by owner, because that is the question the console
// asks: "what can subscribe to this branch?". A key's owner decides only who
// can see and revoke it, so listing by owner would hide a key minted by an
// admin from the person whose branch it opens.
func (s *Store) RealtimeKeysFor(branchName string) ([]KeyInfo, error) {
	rows, err := s.db.Query(
		`SELECT id,name,prefix,created,scope,kind FROM api_keys WHERE scope=? AND kind=? ORDER BY created DESC`,
		strings.TrimSpace(branchName), KindRealtime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KeyInfo{}
	for rows.Next() {
		var k KeyInfo
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.Created, &k.Scope, &k.Kind); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeRealtimeKey deletes one realtime key, and only if it belongs to the
// branch named.
//
// The branch is part of the query rather than checked afterwards because the
// caller was authorized against that branch: without it, the owner of one
// branch could revoke another branch's subscriber by id. It also refuses to
// touch an account or gateway key, which is `fox key revoke`'s business.
func (s *Store) RevokeRealtimeKey(branchName, id string) error {
	res, err := s.db.Exec(`DELETE FROM api_keys WHERE id=? AND scope=? AND kind=?`,
		id, strings.TrimSpace(branchName), KindRealtime)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		// Said as "no such key on this branch" rather than "not yours": the
		// caller may not learn whether the id exists somewhere else.
		return fmt.Errorf("%w: no realtime key %q on branch %q", ErrNoSuchKey, id, branchName)
	}
	return nil
}

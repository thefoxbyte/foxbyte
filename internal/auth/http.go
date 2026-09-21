// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type ctxKey int

const userKey ctxKey = 0
const cookieName = "dbengine_session"

// UserFrom returns the authenticated user attached by Authn.
func UserFrom(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userKey).(User)
	return u, ok
}

func (s *Store) setCookie(w http.ResponseWriter, tok string) {
	secure := strings.HasPrefix(s.cfg.WebOrigin, "https")
	ss := http.SameSiteLaxMode
	// Only a UI hosted on another origin needs the cookie sent cross-site; the
	// console served by the control plane itself keeps the stricter Lax.
	if secure && s.cfg.WebOrigin != s.cfg.PublicURL {
		ss = http.SameSiteNoneMode
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
		Secure: secure, SameSite: ss, Expires: time.Now().Add(sessionTTL),
	})
}

func (s *Store) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
}

// userFromRequest resolves a user via session cookie or API key.
func (s *Store) userFromRequest(r *http.Request) (User, bool) {
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		if u, ok := s.userBySession(c.Value); ok {
			return u, true
		}
	}
	key := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		key = strings.TrimPrefix(h, "Bearer ")
	}
	if key == "" {
		key = r.Header.Get("X-API-Key")
	}
	if key != "" {
		// A scoped key opens one branch through the Gateway and nothing else, so
		// it must not authenticate an HTTP request: that would hand an agent the
		// control plane, and with it every branch its owner can reach.
		if u, scope, ok := s.VerifyKey(key); ok && scope == "" {
			return u, true
		}
	}
	return User{}, false
}

// Authn wraps a handler, requiring a valid session or API key.
func (s *Store) Authn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.userFromRequest(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

// MountPublic registers unauthenticated auth endpoints.
func (s *Store) MountPublic(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/register", s.handleRegister)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /auth/me", s.handleMe)
	mux.HandleFunc("GET /auth/providers", s.handleProviders)
	mux.HandleFunc("GET /auth/oauth/{provider}", s.handleOAuthStart)
	mux.HandleFunc("GET /auth/oauth/{provider}/callback", s.handleOAuthCallback)
}

// MountKeys registers API-key management (must be wrapped in Authn by the caller).
func (s *Store) MountKeys(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/keys", s.handleListKeys)
	mux.HandleFunc("POST /api/keys", s.handleCreateKey)
	mux.HandleFunc("DELETE /api/keys/{id}", s.handleRevokeKey)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Store) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.SignupOpen {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "signups are closed"})
		return
	}
	var b struct{ Email, Password string }
	_ = json.NewDecoder(r.Body).Decode(&b)
	if len(b.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
		return
	}
	u, err := s.CreateUser(b.Email, b.Password)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	tok, _ := s.createSession(u.ID)
	s.setCookie(w, tok)
	writeJSON(w, http.StatusCreated, map[string]any{"user": u})
}

func (s *Store) handleLogin(w http.ResponseWriter, r *http.Request) {
	var b struct{ Email, Password string }
	_ = json.NewDecoder(r.Body).Decode(&b)
	u, err := s.Login(b.Email, b.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	tok, _ := s.createSession(u.ID)
	s.setCookie(w, tok)
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (s *Store) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.deleteSession(c.Value)
	}
	s.clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Store) handleMe(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.userFromRequest(r); ok {
		writeJSON(w, http.StatusOK, map[string]any{"user": u})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": nil})
}

func (s *Store) handleProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"github": s.cfg.GitHub.enabled(),
		"google": s.cfg.Google.enabled(),
		"signup": s.cfg.SignupOpen,
	})
}

func (s *Store) handleListKeys(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	keys, _ := s.listAPIKeys(u.ID)
	if keys == nil {
		keys = []KeyInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Store) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	var b struct{ Name string }
	_ = json.NewDecoder(r.Body).Decode(&b)
	secret, info, err := s.CreateAPIKey(u.ID, b.Name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"key": secret, "info": info})
}

func (s *Store) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	u, _ := UserFrom(r.Context())
	_ = s.revokeAPIKey(u.ID, r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

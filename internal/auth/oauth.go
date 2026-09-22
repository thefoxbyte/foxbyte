// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

func (s *Store) oauthConfig(provider string) (*oauth2.Config, bool) {
	switch provider {
	case "github":
		if !s.cfg.GitHub.enabled() {
			return nil, false
		}
		return &oauth2.Config{
			ClientID: s.cfg.GitHub.ClientID, ClientSecret: s.cfg.GitHub.ClientSecret,
			Endpoint: github.Endpoint, Scopes: []string{"read:user", "user:email"},
			RedirectURL: s.cfg.PublicURL + "/auth/oauth/github/callback",
		}, true
	case "google":
		if !s.cfg.Google.enabled() {
			return nil, false
		}
		return &oauth2.Config{
			ClientID: s.cfg.Google.ClientID, ClientSecret: s.cfg.Google.ClientSecret,
			Endpoint: google.Endpoint, Scopes: []string{"openid", "email", "profile"},
			RedirectURL: s.cfg.PublicURL + "/auth/oauth/google/callback",
		}, true
	}
	return nil, false
}

func (s *Store) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	cfg, ok := s.oauthConfig(r.PathValue("provider"))
	if !ok {
		http.Error(w, "provider not configured", http.StatusNotFound)
		return
	}
	state := randToken(12)
	http.SetCookie(w, s.stateCookie(state, 600))
	http.Redirect(w, r, cfg.AuthCodeURL(state), http.StatusFound)
}

const stateCookieName = "dbengine_oauth_state"

// stateCookie carries the OAuth state between the redirect out and the
// callback. Secure whenever the API is served over HTTPS, so it never travels
// in cleartext, and Lax: the callback is a top-level navigation back from the
// provider, which Lax allows and which is the only way it should arrive.
func (s *Store) stateCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: stateCookieName, Value: value, Path: "/auth/oauth/", HttpOnly: true,
		Secure: strings.HasPrefix(s.cfg.PublicURL, "https"), SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}

func (s *Store) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	cfg, ok := s.oauthConfig(provider)
	if !ok {
		http.Error(w, "provider not configured", http.StatusNotFound)
		return
	}
	st, err := r.Cookie(stateCookieName)
	http.SetCookie(w, s.stateCookie("", -1)) // one use only, whatever happens next
	if err != nil || st.Value == "" || r.URL.Query().Get("state") != st.Value {
		http.Error(w, "bad oauth state", http.StatusBadRequest)
		return
	}
	tok, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "oauth exchange failed", http.StatusBadRequest)
		return
	}
	subject, email, verified, err := fetchIdentity(r.Context(), provider, cfg, tok)
	if err != nil || subject == "" {
		http.Error(w, "could not read identity", http.StatusBadRequest)
		return
	}
	u, err := s.upsertOAuth(provider, subject, email, verified)
	switch {
	case errors.Is(err, errOAuthUnverified), errors.Is(err, errOAuthNoAccount):
		s.Audit(EvOAuthRefused, "", email, clientIP(r), provider+": "+err.Error())
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	case err != nil:
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	s.Audit(EvLoginOK, u.Email, u.Email, clientIP(r), provider)
	sess, _ := s.createSession(u.ID)
	s.setCookie(w, sess)
	http.Redirect(w, r, s.cfg.WebOrigin+"/dashboard", http.StatusFound)
}

// fetchIdentity reads the provider's stable id for the user and their email,
// and whether the provider has verified that email. Only a verified email may
// join or create an account: an unverified one is whatever the user typed.
func fetchIdentity(ctx context.Context, provider string, cfg *oauth2.Config, tok *oauth2.Token) (subject, email string, verified bool, err error) {
	c := cfg.Client(ctx, tok)
	switch provider {
	case "github":
		var u struct {
			ID int64 `json:"id"`
		}
		if err = getJSON(c, "https://api.github.com/user", &u); err != nil {
			return
		}
		subject = fmt.Sprintf("%d", u.ID)
		// The profile's public email carries no verified flag; the emails
		// list does, so the primary address comes from there.
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if getJSON(c, "https://api.github.com/user/emails", &emails) == nil {
			email, verified = githubPrimary(emails)
		}
		return
	case "google":
		var u struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}
		if err = getJSON(c, "https://openidconnect.googleapis.com/v1/userinfo", &u); err != nil {
			return
		}
		return u.Sub, u.Email, u.EmailVerified, nil
	}
	return "", "", false, fmt.Errorf("unknown provider")
}

// githubPrimary picks the primary address from GitHub's emails list.
func githubPrimary(emails []struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}) (string, bool) {
	for _, e := range emails {
		if e.Primary {
			return e.Email, e.Verified
		}
	}
	return "", false
}

func getJSON(c *http.Client, url string, v any) error {
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s", url, string(b))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

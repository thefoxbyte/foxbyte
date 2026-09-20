// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
	http.SetCookie(w, &http.Cookie{Name: "dbengine_oauth_state", Value: state, Path: "/", HttpOnly: true, MaxAge: 600})
	http.Redirect(w, r, cfg.AuthCodeURL(state), http.StatusFound)
}

func (s *Store) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	cfg, ok := s.oauthConfig(provider)
	if !ok {
		http.Error(w, "provider not configured", http.StatusNotFound)
		return
	}
	st, err := r.Cookie("dbengine_oauth_state")
	if err != nil || r.URL.Query().Get("state") != st.Value {
		http.Error(w, "bad oauth state", http.StatusBadRequest)
		return
	}
	tok, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "oauth exchange failed", http.StatusBadRequest)
		return
	}
	subject, email, err := fetchIdentity(r.Context(), provider, cfg, tok)
	if err != nil || subject == "" {
		http.Error(w, "could not read identity", http.StatusBadRequest)
		return
	}
	u, err := s.upsertOAuth(provider, subject, email)
	if err != nil {
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	sess, _ := s.createSession(u.ID)
	s.setCookie(w, sess)
	http.Redirect(w, r, s.cfg.WebOrigin+"/dashboard", http.StatusFound)
}

func fetchIdentity(ctx context.Context, provider string, cfg *oauth2.Config, tok *oauth2.Token) (subject, email string, err error) {
	c := cfg.Client(ctx, tok)
	switch provider {
	case "github":
		var u struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
		}
		if err = getJSON(c, "https://api.github.com/user", &u); err != nil {
			return
		}
		subject, email = fmt.Sprintf("%d", u.ID), u.Email
		if email == "" {
			var emails []struct {
				Email   string `json:"email"`
				Primary bool   `json:"primary"`
			}
			if getJSON(c, "https://api.github.com/user/emails", &emails) == nil {
				for _, e := range emails {
					if e.Primary {
						email = e.Email
					}
				}
			}
		}
		return
	case "google":
		var u struct {
			Sub   string `json:"sub"`
			Email string `json:"email"`
		}
		if err = getJSON(c, "https://openidconnect.googleapis.com/v1/userinfo", &u); err != nil {
			return
		}
		return u.Sub, u.Email, nil
	}
	return "", "", fmt.Errorf("unknown provider")
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

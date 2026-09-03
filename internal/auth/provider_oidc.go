package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/loomtek/vellum/internal/domain"
	"golang.org/x/oauth2"
)

type oidcProvider struct {
	oidcProvider *oidc.Provider
	clientID     string
}

func newOIDCProvider(ctx context.Context, cfg domain.AuthProviderConfig, baseURL string) (provider, *oauth2.Config, error) {
	if cfg.IssuerURL == "" {
		return nil, nil, fmt.Errorf("oidc: issuer_url is required")
	}
	op, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		// Attempt to gracefully handle common trailing slash mismatches
		if strings.HasSuffix(cfg.IssuerURL, "/") {
			op, err = oidc.NewProvider(ctx, strings.TrimSuffix(cfg.IssuerURL, "/"))
		} else {
			op, err = oidc.NewProvider(ctx, cfg.IssuerURL+"/")
		}
		if err != nil {
			return nil, nil, fmt.Errorf("oidc: discover provider: %w", err)
		}
	}
	o2cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     op.Endpoint(),
		RedirectURL:  baseURL + "/api/auth/oidc/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return &oidcProvider{oidcProvider: op, clientID: cfg.ClientID}, o2cfg, nil
}

func (p *oidcProvider) needsNonce() bool { return true }

func (p *oidcProvider) buildAuthURL(o2cfg *oauth2.Config, state, nonce string) string {
	return o2cfg.AuthCodeURL(state, oidc.Nonce(nonce))
}

func (p *oidcProvider) exchange(ctx context.Context, o2cfg *oauth2.Config, code, nonce string) (*userInfo, error) {
	tok, err := o2cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: exchange code: %w", err)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("oidc: no id_token in response")
	}

	verifier := p.oidcProvider.Verifier(&oidc.Config{ClientID: p.clientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: verify id_token: %w", err)
	}

	if nonce != "" && idToken.Nonce != nonce {
		return nil, fmt.Errorf("oidc: nonce mismatch")
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: extract claims: %w", err)
	}

	return &userInfo{
		ProviderID: claims.Sub,
		Email:      claims.Email,
		Name:       claims.Name,
	}, nil
}

package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/loomtek/vellum/internal/config"
	"github.com/loomtek/vellum/internal/domain"
	vlog "github.com/loomtek/vellum/internal/logger"
	"github.com/loomtek/vellum/internal/storage"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var (
	ErrSetupComplete        = errors.New("setup already complete")
	ErrInvalidPassword      = errors.New("invalid password")
	ErrUserNotFound         = errors.New("user not found")
	ErrInvalidAuth          = errors.New("invalid credentials")
	ErrProviderDisabled     = errors.New("provider not enabled")
	ErrPolicyDenied         = errors.New("access denied by policy")
	ErrAlreadyLinked        = errors.New("provider already linked to another account")
	ErrLastProvider         = errors.New("cannot remove your only authentication method")
	ErrLastEnabledProvider  = errors.New("must keep at least one authentication provider enabled")
	// ErrWeakPassword is returned when a password does not meet complexity rules.
	ErrWeakPassword = errors.New("password must be at least 8 characters with uppercase, lowercase, and number")
)

var (
	passwordUpper = regexp.MustCompile(`[A-Z]`)
	passwordLower = regexp.MustCompile(`[a-z]`)
	passwordDigit = regexp.MustCompile(`[0-9]`)
)

// oauthState stores the CSRF state and context for an in-flight OAuth2 flow.
type oauthState struct {
	Nonce    string               // OIDC nonce (empty for non-OIDC providers)
	Action   string               // "login" or "link"
	UserID   string               // populated when Action="link"
	Provider domain.ProviderName
}

// Service orchestrates all authentication flows: local, OAuth2 (GitHub, Google,
// Discord) and OIDC. Provider configurations are loaded from the database and
// can be reloaded at runtime when the admin updates them.
type Service struct {
	db     *storage.DB
	tokens *TokenManager
	cfg    *config.Config

	mu           sync.Mutex
	states       map[string]oauthState               // state → oauthState
	oauth2Cfgs   map[domain.ProviderName]*oauth2.Config
	providerImpls map[domain.ProviderName]provider   // provider-specific logic
}

// NewService creates a Service instance and loads provider configurations from
// the database, falling back to environment variables when the DB has no entry.
func NewService(db *storage.DB, tokens *TokenManager, cfg *config.Config) (*Service, error) {
	svc := &Service{
		db:            db,
		tokens:        tokens,
		cfg:           cfg,
		states:        make(map[string]oauthState),
		oauth2Cfgs:    make(map[domain.ProviderName]*oauth2.Config),
		providerImpls: make(map[domain.ProviderName]provider),
	}
	if err := svc.bootstrapProviderConfigs(); err != nil {
		return nil, err
	}
	if err := svc.ReloadProviders(); err != nil {
		return nil, err
	}
	if err := svc.MigrateExistingUsers(); err != nil {
		return nil, fmt.Errorf("migrate users: %w", err)
	}
	return svc, nil
}

// bootstrapProviderConfigs seeds the database with provider configs derived
// from environment variables the first time the new code runs.
func (s *Service) bootstrapProviderConfigs() error {
	all, err := s.db.ListAuthProviderConfigs()
	if err != nil {
		return err
	}
	if len(all) > 0 {
		return nil // already initialised
	}

	appCfg, _ := s.db.GetConfig()
	method := ""
	if appCfg != nil {
		method = appCfg.AuthMethod
	}

	// Enable local by default (or if AuthMethod was "local").
	if method == "" || method == "local" {
		_ = s.db.SaveAuthProviderConfig(&domain.AuthProviderConfig{
			Name:     domain.ProviderLocal,
			Enabled:  true,
			Policies: []domain.AccessPolicy{},
		})
	}

	// If the instance was configured with OIDC, carry that forward.
	if (method == "oidc" || method == "") && s.cfg.OIDCIssuer != "" {
		_ = s.db.SaveAuthProviderConfig(&domain.AuthProviderConfig{
			Name:         domain.ProviderOIDC,
			Enabled:      true,
			ClientID:     s.cfg.OIDCClientID,
			ClientSecret: s.cfg.OIDCClientSecret,
			IssuerURL:    s.cfg.OIDCIssuer,
			Policies:     []domain.AccessPolicy{},
		})
	}

	// Seed OAuth2 providers from environment if credentials are present.
	if s.cfg.GitHubClientID != "" {
		_ = s.db.SaveAuthProviderConfig(&domain.AuthProviderConfig{
			Name:         domain.ProviderGitHub,
			Enabled:      false, // admin must explicitly enable
			ClientID:     s.cfg.GitHubClientID,
			ClientSecret: s.cfg.GitHubClientSecret,
			Policies:     []domain.AccessPolicy{},
		})
	}
	if s.cfg.GoogleClientID != "" {
		_ = s.db.SaveAuthProviderConfig(&domain.AuthProviderConfig{
			Name:         domain.ProviderGoogle,
			Enabled:      false,
			ClientID:     s.cfg.GoogleClientID,
			ClientSecret: s.cfg.GoogleClientSecret,
			Policies:     []domain.AccessPolicy{},
		})
	}
	if s.cfg.DiscordClientID != "" {
		_ = s.db.SaveAuthProviderConfig(&domain.AuthProviderConfig{
			Name:         domain.ProviderDiscord,
			Enabled:      false,
			ClientID:     s.cfg.DiscordClientID,
			ClientSecret: s.cfg.DiscordClientSecret,
			Policies:     []domain.AccessPolicy{},
		})
	}
	return nil
}

// ReloadProviders re-reads provider configurations from the database and
// rebuilds the internal OAuth2 config map. Call this after the admin updates
// provider settings.
func (s *Service) ReloadProviders() error {
	cfgs, err := s.db.ListAuthProviderConfigs()
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.oauth2Cfgs = make(map[domain.ProviderName]*oauth2.Config)
	s.providerImpls = make(map[domain.ProviderName]provider)

	for _, pc := range cfgs {
		if !pc.Enabled {
			continue
		}
		switch pc.Name {
		case domain.ProviderGitHub:
			impl, o2cfg := newGitHubProvider(pc, s.cfg.BaseURL)
			s.providerImpls[domain.ProviderGitHub] = impl
			s.oauth2Cfgs[domain.ProviderGitHub] = o2cfg

		case domain.ProviderGoogle:
			impl, o2cfg := newGoogleProvider(pc, s.cfg.BaseURL)
			s.providerImpls[domain.ProviderGoogle] = impl
			s.oauth2Cfgs[domain.ProviderGoogle] = o2cfg

		case domain.ProviderDiscord:
			impl, o2cfg := newDiscordProvider(pc, s.cfg.BaseURL)
			s.providerImpls[domain.ProviderDiscord] = impl
			s.oauth2Cfgs[domain.ProviderDiscord] = o2cfg

		case domain.ProviderOIDC:
			impl, o2cfg, err := newOIDCProvider(context.Background(), pc, s.cfg.BaseURL)
			if err != nil {
				vlog.Security("oidc_provider_init_failed", "error", err.Error())
				continue
			}
			s.providerImpls[domain.ProviderOIDC] = impl
			s.oauth2Cfgs[domain.ProviderOIDC] = o2cfg
		}
	}
	return nil
}

// MigrateExistingUsers creates ProviderIdentity records for users that were
// stored before the multi-provider migration. Idempotent — safe to call on every boot.
func (s *Service) MigrateExistingUsers() error {
	users, err := s.db.ListUsers()
	if err != nil {
		return err
	}

	now := time.Now()
	for _, u := range users {
		u := u

		// Migrate Status from legacy Active field.
		if u.Status == "" {
			if u.Active {
				u.Status = domain.UserStatusActive
			} else {
				u.Status = domain.UserStatusSuspended
			}
			_ = s.db.UpdateUser(&u)
		}

		// Migrate local password to ProviderIdentity.
		if u.PasswordHash != "" && u.Provider == domain.AuthProviderLocal {
			_, err := s.db.GetProviderIdentityByUserAndProvider(u.ID, domain.ProviderLocal)
			if errors.Is(err, storage.ErrNotFound) {
				pi := &domain.ProviderIdentity{
					ID:           uuid.NewString(),
					UserID:       u.ID,
					Provider:     domain.ProviderLocal,
					ProviderID:   u.ID,
					Email:        u.Email,
					PasswordHash: u.PasswordHash,
					LinkedAt:     now,
				}
				_ = s.db.CreateProviderIdentity(pi)
			}
		}

		// Migrate OIDC subject to ProviderIdentity.
		if u.OIDCSub != "" && u.Provider == domain.AuthProviderOIDC {
			_, err := s.db.GetProviderIdentityByUserAndProvider(u.ID, domain.ProviderOIDC)
			if errors.Is(err, storage.ErrNotFound) {
				pi := &domain.ProviderIdentity{
					ID:         uuid.NewString(),
					UserID:     u.ID,
					Provider:   domain.ProviderOIDC,
					ProviderID: u.OIDCSub,
					Email:      u.Email,
					LinkedAt:   now,
				}
				_ = s.db.CreateProviderIdentity(pi)
			}
		}
	}
	return nil
}

// ---- Setup ----

func (s *Service) SetupStatus() (*domain.AppConfig, error) {
	return s.db.GetConfig()
}

// HasUsers reports whether any user records exist in the database.
func (s *Service) HasUsers() (bool, error) {
	users, err := s.db.ListUsers()
	if err != nil {
		return false, err
	}
	return len(users) > 0, nil
}

// RegisterAdmin creates the first administrator account using local credentials.
// It returns ErrSetupComplete if any user already exists. On success the admin
// is immediately issued a session so the browser can proceed without a second
// login step.
func (s *Service) RegisterAdmin(name, email, password string) (*domain.User, string, string, string, error) {
	users, err := s.db.ListUsers()
	if err != nil {
		return nil, "", "", "", err
	}
	if len(users) > 0 {
		return nil, "", "", "", ErrSetupComplete
	}
	if err := validatePassword(password); err != nil {
		return nil, "", "", "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("hash password: %w", err)
	}
	now := time.Now()
	u := &domain.User{
		ID:        uuid.NewString(),
		Email:     email,
		Name:      name,
		Role:      domain.RoleAdmin,
		Status:    domain.UserStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.db.CreateUser(u); err != nil {
		return nil, "", "", "", fmt.Errorf("create admin: %w", err)
	}
	// Record admin ID and mark setup complete.
	cfg, _ := s.db.GetConfig()
	if cfg != nil {
		cfg.AdminUserID = u.ID
		cfg.SetupComplete = true
		_ = s.db.SaveConfig(cfg)
	}
	// Create the local ProviderIdentity.
	pi := &domain.ProviderIdentity{
		ID:           uuid.NewString(),
		UserID:       u.ID,
		Provider:     domain.ProviderLocal,
		ProviderID:   u.ID,
		Email:        u.Email,
		PasswordHash: string(hash),
		LinkedAt:     now,
	}
	if err := s.db.CreateProviderIdentity(pi); err != nil {
		return nil, "", "", "", fmt.Errorf("create identity: %w", err)
	}
	// Ensure the local provider is enabled.
	localCfg, err := s.db.GetAuthProviderConfig(domain.ProviderLocal)
	if err != nil || localCfg == nil {
		_ = s.db.SaveAuthProviderConfig(&domain.AuthProviderConfig{
			Name: domain.ProviderLocal, Enabled: true, Policies: []domain.AccessPolicy{},
		})
	} else if !localCfg.Enabled {
		localCfg.Enabled = true
		_ = s.db.SaveAuthProviderConfig(localCfg)
	}
	if err := s.ReloadProviders(); err != nil {
		return nil, "", "", "", err
	}
	access, refresh, familyID, err := s.tokens.IssueTokens(u.ID, u.Role)
	if err != nil {
		return nil, "", "", "", err
	}
	return u, access, refresh, familyID, nil
}

func (s *Service) CompleteSetup(method string) error {
	cfg, err := s.db.GetConfig()
	if err != nil {
		return err
	}
	if cfg.SetupComplete {
		return ErrSetupComplete
	}
	cfg.AuthMethod = method
	cfg.SetupComplete = true
	if err := s.db.SaveConfig(cfg); err != nil {
		return err
	}
	// Ensure the chosen provider is enabled.
	switch method {
	case "local":
		_ = s.db.SaveAuthProviderConfig(&domain.AuthProviderConfig{
			Name: domain.ProviderLocal, Enabled: true, Policies: []domain.AccessPolicy{},
		})
	case "oidc":
		existing, _ := s.db.GetAuthProviderConfig(domain.ProviderOIDC)
		if existing == nil {
			_ = s.db.SaveAuthProviderConfig(&domain.AuthProviderConfig{
				Name:         domain.ProviderOIDC,
				Enabled:      true,
				ClientID:     s.cfg.OIDCClientID,
				ClientSecret: s.cfg.OIDCClientSecret,
				IssuerURL:    s.cfg.OIDCIssuer,
				Policies:     []domain.AccessPolicy{},
			})
		}
	}
	return s.ReloadProviders()
}

// ---- Provider config management ----

// GetProviderConfig returns the full configuration for a provider.
func (s *Service) GetProviderConfig(name domain.ProviderName) (*domain.AuthProviderConfig, error) {
	return s.db.GetAuthProviderConfig(name)
}

// ListProviderConfigs returns all known provider configurations.
func (s *Service) ListProviderConfigs() ([]domain.AuthProviderConfig, error) {
	return s.db.ListAuthProviderConfigs()
}

// SaveProviderConfig persists a provider configuration and reloads all providers.
// Validates: (1) at least one provider remains globally enabled, and (2) the
// calling admin retains at least one active login method.
func (s *Service) SaveProviderConfig(pc *domain.AuthProviderConfig, callerID string) error {
	if !pc.Enabled {
		if err := s.validateAtLeastOneProvider(pc.Name); err != nil {
			return err
		}
		if err := s.validateNotLastProvider(callerID, pc.Name); err != nil {
			return err
		}
	}
	if err := s.db.SaveAuthProviderConfig(pc); err != nil {
		return err
	}
	return s.ReloadProviders()
}

// validateAtLeastOneProvider returns ErrLastEnabledProvider if disabling
// providerToDisable would leave zero providers enabled globally.
func (s *Service) validateAtLeastOneProvider(providerToDisable domain.ProviderName) error {
	cfgs, err := s.db.ListAuthProviderConfigs()
	if err != nil {
		return err
	}
	remaining := 0
	for _, c := range cfgs {
		if c.Name != providerToDisable && c.Enabled {
			remaining++
		}
	}
	if remaining == 0 {
		return ErrLastEnabledProvider
	}
	return nil
}

// validateNotLastProvider returns ErrLastProvider if disabling providerName
// would remove the caller's only authentication method.
func (s *Service) validateNotLastProvider(callerID string, providerToDisable domain.ProviderName) error {
	identities, err := s.db.GetProviderIdentitiesByUser(callerID)
	if err != nil {
		return err
	}
	activeProviders := 0
	for _, pi := range identities {
		if pi.Provider == providerToDisable {
			continue
		}
		// Check if that provider is still enabled.
		cfg, err := s.db.GetAuthProviderConfig(pi.Provider)
		if err != nil || !cfg.Enabled {
			continue
		}
		activeProviders++
	}
	if activeProviders == 0 {
		return ErrLastProvider
	}
	return nil
}

// ---- Local auth ----

func validatePassword(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword
	}
	if !passwordUpper.MatchString(password) || !passwordLower.MatchString(password) || !passwordDigit.MatchString(password) {
		return ErrWeakPassword
	}
	return nil
}

// LoginLocal authenticates a user with email and password.
func (s *Service) LoginLocal(email, password string) (*domain.User, string, string, string, error) {
	u, err := s.db.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, "", "", "", ErrInvalidAuth
		}
		return nil, "", "", "", err
	}

	if !u.IsActive() {
		vlog.Security("login_inactive_user", "email", email, "user", u.ID)
		return nil, "", "", "", ErrInvalidAuth
	}

	pi, err := s.db.GetProviderIdentityByUserAndProvider(u.ID, domain.ProviderLocal)
	if err != nil {
		return nil, "", "", "", ErrInvalidAuth
	}

	if err := bcrypt.CompareHashAndPassword([]byte(pi.PasswordHash), []byte(password)); err != nil {
		vlog.Security("login_failed", "email", email)
		return nil, "", "", "", ErrInvalidAuth
	}

	access, refresh, familyID, err := s.tokens.IssueTokens(u.ID, u.Role)
	if err != nil {
		return nil, "", "", "", err
	}
	return u, access, refresh, familyID, nil
}

// ---- OAuth2 / OIDC flows ----

// GetProviderRedirect generates the authorization URL for an OAuth2/OIDC login flow.
func (s *Service) GetProviderRedirect(providerName domain.ProviderName) (authURL string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	o2cfg, ok := s.oauth2Cfgs[providerName]
	if !ok {
		return "", ErrProviderDisabled
	}
	impl := s.providerImpls[providerName]

	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	nonce := ""
	if impl.needsNonce() {
		nonceBytes := make([]byte, 16)
		rand.Read(nonceBytes)
		nonce = hex.EncodeToString(nonceBytes)
	}

	s.states[state] = oauthState{
		Nonce:    nonce,
		Action:   "login",
		Provider: providerName,
	}

	authURL = impl.buildAuthURL(o2cfg, state, nonce)
	return authURL, nil
}

// GetLinkRedirect generates the authorization URL for linking a provider to an existing account.
func (s *Service) GetLinkRedirect(providerName domain.ProviderName, userID string) (authURL string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	o2cfg, ok := s.oauth2Cfgs[providerName]
	if !ok {
		return "", ErrProviderDisabled
	}
	impl := s.providerImpls[providerName]

	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	nonce := ""
	if impl.needsNonce() {
		nonceBytes := make([]byte, 16)
		rand.Read(nonceBytes)
		nonce = hex.EncodeToString(nonceBytes)
	}

	s.states[state] = oauthState{
		Nonce:    nonce,
		Action:   "link",
		UserID:   userID,
		Provider: providerName,
	}

	authURL = impl.buildAuthURL(o2cfg, state, nonce)
	return authURL, nil
}

// HandleProviderCallback processes the OAuth2/OIDC authorization code. Returns
// user, tokens (for login), or empty tokens (for link). The action field in the
// returned oauthState copy tells the caller which case occurred.
func (s *Service) HandleProviderCallback(code, state string) (*domain.User, string, string, string, string, error) {
	s.mu.Lock()
	st, ok := s.states[state]
	if ok {
		delete(s.states, state)
	}
	s.mu.Unlock()

	if !ok {
		vlog.Security("oauth_invalid_state", "state", state)
		return nil, "", "", "", "", errors.New("invalid state parameter")
	}

	s.mu.Lock()
	o2cfg, cfgOk := s.oauth2Cfgs[st.Provider]
	impl, implOk := s.providerImpls[st.Provider]
	s.mu.Unlock()

	if !cfgOk || !implOk {
		return nil, "", "", "", "", ErrProviderDisabled
	}

	info, err := impl.exchange(context.Background(), o2cfg, code, st.Nonce)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("exchange: %w", err)
	}

	// Validate access policies.
	if err := s.checkPolicies(st.Provider, info); err != nil {
		vlog.Security("policy_denied",
			"provider", st.Provider,
			"email", info.Email,
			"username", info.Username,
			"provider_id", info.ProviderID,
		)
		return nil, "", "", "", "", err
	}

	if st.Action == "link" {
		if err := s.linkProviderToUser(st.UserID, st.Provider, info); err != nil {
			return nil, "", "", "", "", err
		}
		u, err := s.db.GetUserByID(st.UserID)
		if err != nil {
			return nil, "", "", "", "", err
		}
		return u, "", "", "", "link", nil
	}

	// Login flow — find or create user.
	u, access, refresh, familyID, err := s.loginOrRegisterOAuth(st.Provider, info)
	if err != nil {
		return nil, "", "", "", "", err
	}
	return u, access, refresh, familyID, "login", nil
}

func (s *Service) loginOrRegisterOAuth(provider domain.ProviderName, info *userInfo) (*domain.User, string, string, string, error) {
	// Try to find by provider identity.
	pi, err := s.db.GetProviderIdentityByProviderID(provider, info.ProviderID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, "", "", "", err
	}

	var u *domain.User
	if pi != nil {
		u, err = s.db.GetUserByID(pi.UserID)
		if err != nil {
			return nil, "", "", "", err
		}
	} else {
		// Try by email.
		u, err = s.db.GetUserByEmail(info.Email)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return nil, "", "", "", err
		}
	}

	if u == nil {
		// New OAuth users are always regular users. Admin is only created via RegisterAdmin.
		now := time.Now()
		u = &domain.User{
			ID:        uuid.NewString(),
			Email:     info.Email,
			Name:      info.Name,
			Role:      domain.RoleUser,
			Status:    domain.UserStatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.db.CreateUser(u); err != nil && !errors.Is(err, storage.ErrConflict) {
			return nil, "", "", "", fmt.Errorf("create user: %w", err)
		}
		if errors.Is(err, storage.ErrConflict) {
			// Race: another goroutine created the user; re-fetch.
			u, err = s.db.GetUserByEmail(info.Email)
			if err != nil {
				return nil, "", "", "", err
			}
		}
	}

	if !u.IsActive() {
		vlog.Security("oauth_login_inactive_user", "provider", provider, "user", u.ID)
		return nil, "", "", "", ErrInvalidAuth
	}

	// Ensure ProviderIdentity exists.
	if pi == nil {
		_ = s.linkProviderToUser(u.ID, provider, info)
	}

	access, refresh, familyID, err := s.tokens.IssueTokens(u.ID, u.Role)
	if err != nil {
		return nil, "", "", "", err
	}
	return u, access, refresh, familyID, nil
}

func (s *Service) linkProviderToUser(userID string, provider domain.ProviderName, info *userInfo) error {
	// Check that the provider ID is not already linked to a different user.
	existing, err := s.db.GetProviderIdentityByProviderID(provider, info.ProviderID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	if existing != nil && existing.UserID != userID {
		return ErrAlreadyLinked
	}
	if existing != nil {
		return nil // already linked to this user, nothing to do
	}

	pi := &domain.ProviderIdentity{
		ID:         uuid.NewString(),
		UserID:     userID,
		Provider:   provider,
		ProviderID: info.ProviderID,
		Email:      info.Email,
		Username:   info.Username,
		LinkedAt:   time.Now(),
	}
	return s.db.CreateProviderIdentity(pi)
}

// UnlinkProvider removes a provider from the user's account.
func (s *Service) UnlinkProvider(userID string, provider domain.ProviderName) error {
	pi, err := s.db.GetProviderIdentityByUserAndProvider(userID, provider)
	if err != nil {
		return err
	}
	if err := s.validateNotLastProvider(userID, provider); err != nil {
		return err
	}
	return s.db.DeleteProviderIdentity(pi)
}

// ListUserProviders returns all provider identities linked to a user (passwords omitted).
func (s *Service) ListUserProviders(userID string) ([]domain.ProviderIdentity, error) {
	pis, err := s.db.GetProviderIdentitiesByUser(userID)
	if err != nil {
		return nil, err
	}
	for i := range pis {
		pis[i].PasswordHash = ""
	}
	return pis, nil
}

// ---- Access policies ----

func (s *Service) checkPolicies(provider domain.ProviderName, info *userInfo) error {
	cfg, err := s.db.GetAuthProviderConfig(provider)
	if err != nil || len(cfg.Policies) == 0 {
		return nil // open access
	}
	for _, p := range cfg.Policies {
		switch p.Type {
		case domain.PolicyTypeEmail:
			// Exact match.
			if strings.EqualFold(p.Value, info.Email) {
				return nil
			}
			// Domain match: "@empresa.com" allows any address from that domain.
			if strings.HasPrefix(p.Value, "@") {
				if strings.HasSuffix(strings.ToLower(info.Email), strings.ToLower(p.Value)) {
					return nil
				}
			}
		case domain.PolicyTypeUsername:
			if strings.EqualFold(p.Value, info.Username) {
				return nil
			}
		case domain.PolicyTypeID:
			if p.Value == info.ProviderID {
				return nil
			}
		case domain.PolicyTypeSub:
			if p.Value == info.ProviderID {
				return nil
			}
		}
	}
	return ErrPolicyDenied
}

// ---- Session management (delegated to TokenManager) ----

func (s *Service) RefreshSession(familyID, refreshToken, remoteAddr string) (string, string, string, error) {
	family, err := s.db.GetFamily(familyID)
	if err != nil {
		return "", "", "", fmt.Errorf("get family: %w", err)
	}
	u, err := s.db.GetUserByID(family.UserID)
	if err != nil {
		return "", "", "", fmt.Errorf("get user: %w", err)
	}
	return s.tokens.RefreshTokensWithFamily(familyID, refreshToken, remoteAddr, u.Role)
}

func (s *Service) Logout(familyID string) error {
	return s.tokens.RevokeFamily(familyID)
}

// InvalidateUserSessions revokes all active token families for a user.
// Called when a user is suspended or archived.
func (s *Service) InvalidateUserSessions(userID string) {
	s.tokens.RevokeAllForUser(userID)
}

// ---- User management ----

// CreatePendingUser creates a user account with status=pending (no credentials yet).
// The caller must follow up with CreateInvitation.
func (s *Service) CreatePendingUser(email, name string) (*domain.User, error) {
	now := time.Now()
	u := &domain.User{
		ID:        uuid.NewString(),
		Email:     email,
		Name:      name,
		Role:      domain.RoleUser,
		Status:    domain.UserStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.db.CreateUser(u); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			return nil, errors.New("email already registered")
		}
		return nil, err
	}
	return u, nil
}

// SetLocalPassword sets or replaces the bcrypt-hashed password for a user.
// Used when accepting an invitation.
func (s *Service) SetLocalPassword(userID, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	u, err := s.db.GetUserByID(userID)
	if err != nil {
		return err
	}

	pi, err := s.db.GetProviderIdentityByUserAndProvider(userID, domain.ProviderLocal)
	if errors.Is(err, storage.ErrNotFound) {
		// First-time password setup (accepting invitation).
		pi = &domain.ProviderIdentity{
			ID:           uuid.NewString(),
			UserID:       userID,
			Provider:     domain.ProviderLocal,
			ProviderID:   userID,
			Email:        u.Email,
			PasswordHash: string(hash),
			LinkedAt:     time.Now(),
		}
		return s.db.CreateProviderIdentity(pi)
	}
	if err != nil {
		return err
	}
	pi.PasswordHash = string(hash)
	return s.db.UpdateProviderIdentity(pi)
}

// ChangePassword verifies the old password and sets a new one.
func (s *Service) ChangePassword(userID, oldPassword, newPassword string) error {
	pi, err := s.db.GetProviderIdentityByUserAndProvider(userID, domain.ProviderLocal)
	if err != nil {
		return ErrInvalidAuth
	}
	if err := bcrypt.CompareHashAndPassword([]byte(pi.PasswordHash), []byte(oldPassword)); err != nil {
		return ErrInvalidAuth
	}
	return s.SetLocalPassword(userID, newPassword)
}

// SuspendUser blocks a user from logging in and revokes active sessions.
func (s *Service) SuspendUser(userID string) error {
	u, err := s.db.GetUserByID(userID)
	if err != nil {
		return err
	}
	u.Status = domain.UserStatusSuspended
	u.UpdatedAt = time.Now()
	if err := s.db.UpdateUser(u); err != nil {
		return err
	}
	s.InvalidateUserSessions(userID)
	return nil
}

// RestoreUser re-activates a suspended user.
func (s *Service) RestoreUser(userID string) error {
	u, err := s.db.GetUserByID(userID)
	if err != nil {
		return err
	}
	u.Status = domain.UserStatusActive
	u.UpdatedAt = time.Now()
	return s.db.UpdateUser(u)
}

// ArchiveUser permanently deactivates a user and revokes sessions.
func (s *Service) ArchiveUser(userID string) error {
	u, err := s.db.GetUserByID(userID)
	if err != nil {
		return err
	}
	u.Status = domain.UserStatusArchived
	u.UpdatedAt = time.Now()
	if err := s.db.UpdateUser(u); err != nil {
		return err
	}
	s.InvalidateUserSessions(userID)
	return nil
}

// ---- Enabled provider list (for frontend) ----

// EnabledProviders returns the names of all currently enabled providers.
func (s *Service) EnabledProviders() []domain.ProviderName {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]domain.ProviderName, 0, len(s.oauth2Cfgs))
	// Always include local if its config exists.
	if cfg, err := s.db.GetAuthProviderConfig(domain.ProviderLocal); err == nil && cfg.Enabled {
		result = append(result, domain.ProviderLocal)
	}
	for name := range s.oauth2Cfgs {
		result = append(result, name)
	}
	return result
}

// ProviderLabels returns a map of provider names to their configured display names.
func (s *Service) ProviderLabels() map[domain.ProviderName]string {
	cfgs, err := s.db.ListAuthProviderConfigs()
	labels := make(map[domain.ProviderName]string)
	if err != nil {
		return labels
	}
	for _, c := range cfgs {
		if c.DisplayName != "" {
			labels[c.Name] = c.DisplayName
		}
	}
	return labels
}

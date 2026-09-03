package domain

import "time"

// Role represents the authorization level of a user within the system.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// UserStatus represents the operational state of a user account.
type UserStatus string

const (
	UserStatusPending   UserStatus = "pending"   // invitation sent, not yet accepted
	UserStatusActive    UserStatus = "active"     // normal access
	UserStatusSuspended UserStatus = "suspended"  // temporarily blocked by admin
	UserStatusArchived  UserStatus = "archived"   // permanently deactivated (not deleted)
)

// ProviderName identifies an authentication provider.
type ProviderName string

const (
	ProviderLocal   ProviderName = "local"
	ProviderGitHub  ProviderName = "github"
	ProviderGoogle  ProviderName = "google"
	ProviderDiscord ProviderName = "discord"
	ProviderOIDC    ProviderName = "oidc"
)

// AuthProvider is kept for backward-compatible deserialization of old DB records.
// Deprecated: new code must use ProviderName.
type AuthProvider string

const (
	AuthProviderLocal AuthProvider = "local"
	AuthProviderOIDC  AuthProvider = "oidc"
)

// User holds account information for a registered user. The authentication
// credentials are stored separately in ProviderIdentity records.
type User struct {
	ID        string     `json:"id"`
	Email     string     `json:"email"`
	Name      string     `json:"name"`
	Role      Role       `json:"role"`
	Status    UserStatus `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`

	// Legacy fields preserved for backward-compatible deserialization of
	// records written before the multi-provider migration. New code must
	// read credentials from ProviderIdentity, not from these fields.
	PasswordHash string       `json:"password_hash,omitempty"`
	Provider     AuthProvider `json:"provider,omitempty"`
	OIDCSub      string       `json:"oidc_sub,omitempty"`
	Active       bool         `json:"active,omitempty"`
}

// IsActive reports whether the user is allowed to authenticate.
// Falls back to the legacy Active field for records written before migration.
func (u *User) IsActive() bool {
	if u.Status == "" {
		return u.Active
	}
	return u.Status == UserStatusActive
}

// ProviderIdentity links a user account to an external identity provider.
// One user may have multiple identities (one per linked provider).
type ProviderIdentity struct {
	ID           string       `json:"id"`
	UserID       string       `json:"user_id"`
	Provider     ProviderName `json:"provider"`
	ProviderID   string       `json:"provider_id"`             // external identifier (GitHub user ID, OIDC sub, etc.)
	Email        string       `json:"email"`                   // email as reported by the provider
	Username     string       `json:"username,omitempty"`      // login name for GitHub / Discord
	PasswordHash string       `json:"password_hash,omitempty"` // bcrypt hash — local provider only
	LinkedAt     time.Time    `json:"linked_at"`
}

// AccessPolicyType defines which user attribute is matched by an access policy.
type AccessPolicyType string

const (
	PolicyTypeEmail    AccessPolicyType = "email"
	PolicyTypeUsername AccessPolicyType = "username"
	PolicyTypeID       AccessPolicyType = "id"
	PolicyTypeSub      AccessPolicyType = "sub" // OIDC subject identifier
)

// AccessPolicy restricts who may authenticate through a specific provider.
// An empty policy list means the provider is open to any valid account.
type AccessPolicy struct {
	ID    string           `json:"id"`
	Type  AccessPolicyType `json:"type"`
	Value string           `json:"value"`
}

// AuthProviderConfig stores runtime configuration and access policies for one
// authentication provider. Persisted in the database and editable by admins.
type AuthProviderConfig struct {
	Name         ProviderName   `json:"name"`
	Enabled      bool           `json:"enabled"`
	DisplayName  string         `json:"display_name,omitempty"` // Custom name for the login button
	ClientID     string         `json:"client_id,omitempty"`
	ClientSecret string         `json:"client_secret,omitempty"`
	IssuerURL    string         `json:"issuer_url,omitempty"` // OIDC only
	Policies     []AccessPolicy `json:"policies"`
}

// Invitation represents a time-limited registration link for local-auth users.
// The admin creates invitations; the recipient sets their password via the link.
type Invitation struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Token     string     `json:"token"`                 // 32-byte cryptographically random hex string
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	RenewedAt *time.Time `json:"renewed_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Project groups captured emails under a common scope with configurable sender
// allowlists and optional storage quotas. Soft-delete is tracked via DeletedAt.
type Project struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Senders      []string   `json:"senders"`
	StorageLimit int64      `json:"storage_limit"` // bytes; 0 means unlimited
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	Active       bool       `json:"active"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}

// ProjectMember represents the association between a user and a project.
type ProjectMember struct {
	ProjectID string    `json:"project_id"`
	UserID    string    `json:"user_id"`
	AddedAt   time.Time `json:"added_at"`
}

// Email stores a captured SMTP message along with parsed metadata, read status,
// and soft-delete fields used by the trash system.
type Email struct {
	ID             string              `json:"id"`
	ProjectID      string              `json:"project_id"`
	MessageID      string              `json:"message_id"`
	From           string              `json:"from"`
	To             []string            `json:"to"`
	CC             []string            `json:"cc"`
	Subject        string              `json:"subject"`
	TextBody       string              `json:"text_body"`
	HTMLBody       string              `json:"html_body"`
	Attachments    []Attachment        `json:"attachments"`
	ReceivedAt     time.Time           `json:"received_at"`
	ReadBy         []string            `json:"read_by"`
	Size           int64               `json:"size"`
	SpamScore      float64             `json:"spam_score"`
	RawHeaders     map[string][]string `json:"raw_headers,omitempty"`
	DeletedAt      *time.Time          `json:"deleted_at,omitempty"`
	PurgeAt        *time.Time          `json:"purge_at,omitempty"`
	ProjectDeleted bool                `json:"project_deleted,omitempty"`
}

// Attachment represents a single file attached to a captured email.
type Attachment struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Data        []byte `json:"data"`
}

// TokenFamily groups refresh tokens issued within the same authentication session.
// Token rotation and replay detection operate at the family level.
type TokenFamily struct {
	FamilyID    string        `json:"family_id"`
	UserID      string        `json:"user_id"`
	CreatedAt   time.Time     `json:"created_at"`
	Invalidated bool          `json:"invalidated"`
	Tokens      []TokenRecord `json:"tokens"`
}

// TokenRecord tracks an individual refresh token within a family, including its
// issuance, expiration, and optional usage timestamp for replay detection.
type TokenRecord struct {
	TokenID   string     `json:"token_id"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}

// AppConfig stores global application state such as initial setup completion,
// the chosen authentication method, and the persisted JWT signing secret.
type AppConfig struct {
	SetupComplete bool   `json:"setup_complete"`
	AuthMethod    string `json:"auth_method"`
	AdminUserID   string `json:"admin_user_id,omitempty"`
	JWTSecret     string `json:"jwt_secret,omitempty"`
}

// SMTPRelayConfig holds the connection parameters for the outbound SMTP relay
// used to forward captured emails to external recipients.
type SMTPRelayConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	FromAddress string `json:"from_address"`
	UseTLS      bool   `json:"use_tls"`
	Enabled     bool   `json:"enabled"`
}

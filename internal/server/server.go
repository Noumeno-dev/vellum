package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimid "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/loomtek/vellum/internal/auth"
	"github.com/loomtek/vellum/internal/config"
	"github.com/loomtek/vellum/internal/domain"
	vlog "github.com/loomtek/vellum/internal/logger"
	mailhandler "github.com/loomtek/vellum/internal/mail"
	mid "github.com/loomtek/vellum/internal/middleware"
	projhandler "github.com/loomtek/vellum/internal/project"
	smtprelay "github.com/loomtek/vellum/internal/smtp"
	"github.com/loomtek/vellum/internal/storage"
	userhandler "github.com/loomtek/vellum/internal/user"
)

// Server is the main HTTP server that wires together authentication, email
// handlers, project management, SSE notifications, SMTP relay endpoints, and
// the embedded SPA frontend.
type Server struct {
	router  http.Handler
	authSvc *auth.Service
	tokens  *auth.TokenManager
	db      *storage.DB
	cfg     *config.Config
	hub     *SSEHub
	addr    string
}

// New creates a Server, starts the SSE hub, and launches the background purge
// job for expired trashed emails.
func New(cfg *config.Config, db *storage.DB, authSvc *auth.Service, tokens *auth.TokenManager, staticFS fs.FS) *Server {
	hub := NewSSEHub()
	go hub.Run()

	s := &Server{
		authSvc: authSvc,
		tokens:  tokens,
		db:      db,
		cfg:     cfg,
		hub:     hub,
		addr:    fmt.Sprintf(":%d", cfg.Port),
	}
	s.router = s.buildRouter(staticFS)
	go s.runPurgeJob()
	return s
}

// Notify implements smtp.Notifier, forwarding captured emails to the SSE hub.
func (s *Server) Notify(e *domain.Email) {
	s.hub.Broadcast(e)
}

// Start begins listening for HTTP connections on the configured port.
func (s *Server) Start() error {
	slog.Info("http server listening", "addr", s.addr)
	return http.ListenAndServe(s.addr, s.router)
}

func (s *Server) buildRouter(staticFS fs.FS) http.Handler {
	r := chi.NewRouter()

	r.Use(chimid.RealIP)
	r.Use(chimid.Recoverer)
	r.Use(mid.SecurityHeaders)
	r.Use(mid.RequestLogger)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{s.cfg.BaseURL},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Route("/api", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Use(chimid.Timeout(60 * time.Second))
			s.authRoutes(r)
		})

		r.Group(func(r chi.Router) {
			r.Use(mid.Auth(s.tokens))

			// SSE sin timeout — la conexión es persistente por diseño
			r.Get("/events", s.handleSSE)

			r.Group(func(r chi.Router) {
				r.Use(chimid.Timeout(60 * time.Second))

				r.Get("/smtp/status", s.handleSMTPStatus)
				r.Post("/analyzer", s.handleAnalyzeHTML)

				// Mi perfil — proveedores vinculados y gestión de contraseña.
				r.Get("/me/providers", s.handleListMyProviders)
				r.Delete("/me/providers/{provider}", s.handleUnlinkProvider)
				r.Post("/me/password", s.handleChangePassword)

				// Link start (requiere auth — guarda el userID en el estado OAuth).
				r.Get("/auth/{provider}/link/start", s.handleLinkStart)

				r.Route("/relay-addresses", func(r chi.Router) {
					r.Get("/", s.handleRelayAddressList)
					r.Post("/", s.handleRelayAddressAdd)
					r.Delete("/", s.handleRelayAddressDelete)
				})

				r.Route("/users", func(r chi.Router) {
					r.With(mid.RequireAdmin).Get("/", userhandler.HandleList(s.db))
					r.Get("/{id}", userhandler.HandleGet(s.db))
					r.Put("/{id}", userhandler.HandleUpdate(s.db))
				})

				r.Route("/projects", func(r chi.Router) {
					r.Get("/", projhandler.HandleList(s.db))
					r.Get("/unread-counts", projhandler.HandleUnreadCounts(s.db))
					r.With(mid.RequireAdmin).Post("/", projhandler.HandleCreate(s.db))
					r.Route("/{id}", func(r chi.Router) {
						r.Get("/", projhandler.HandleGet(s.db))
						r.With(mid.RequireAdmin).Put("/", projhandler.HandleUpdate(s.db))
						r.With(mid.RequireAdmin).Delete("/", projhandler.HandleDelete(s.db))
						r.With(mid.RequireAdmin).Get("/members", projhandler.HandleListMembers(s.db))
						r.With(mid.RequireAdmin).Post("/members", projhandler.HandleAddMember(s.db))
						r.With(mid.RequireAdmin).Delete("/members/{uid}", projhandler.HandleRemoveMember(s.db))
						r.Get("/storage", projhandler.HandleProjectStorage(s.db))
						r.Get("/emails", mailhandler.HandleList(s.db))
						r.Get("/emails/trash", mailhandler.HandleListTrash(s.db))
						r.Get("/emails/trash/stats", mailhandler.HandleTrashStats(s.db))
						r.Post("/emails/trash/restore", mailhandler.HandleRestoreEmails(s.db))
						r.Delete("/emails/trash/{eid}", mailhandler.HandleDeleteTrashedEmail(s.db))
						r.Delete("/emails/trash", mailhandler.HandlePurgeProjectTrash(s.db))
						r.Get("/emails/{eid}", mailhandler.HandleGet(s.db))
						r.Delete("/emails/{eid}", mailhandler.HandleDelete(s.db))
						r.Post("/emails/{eid}/read", mailhandler.HandleMarkRead(s.db))
						r.Get("/emails/{eid}/analysis", mailhandler.HandleAnalyze(s.db))
						r.Post("/emails/{eid}/relay", mailhandler.HandleRelayEmail(s.db))
					})
				})

				r.With(mid.RequireAdmin).Route("/admin", func(r chi.Router) {
					r.Get("/emails", mailhandler.HandleListAll(s.db))
					r.Delete("/emails/{eid}", mailhandler.HandleDeleteAny(s.db))
					r.Delete("/projects/{id}/emails", mailhandler.HandleDeleteAllByProject(s.db))
					r.Get("/projects/trash", projhandler.HandleListTrashedProjects(s.db))
					r.Get("/projects/storage-usages", projhandler.HandleStorageUsages(s.db))
					r.Post("/projects/{id}/restore", projhandler.HandleRestoreProject(s.db))
					r.Delete("/projects/{id}/purge", projhandler.HandlePurgeProject(s.db))
					r.Get("/smtp", s.handleSMTPGet)
					r.Put("/smtp", s.handleSMTPSave)
					r.Post("/smtp/test", s.handleSMTPTest)

					// Auth provider management.
					r.Get("/auth/providers", s.handleListProviders)
					r.Put("/auth/providers/{name}", s.handleSaveProvider)

					// User management (new).
					r.Post("/users", s.handleCreateUser)
					r.Put("/users/{id}/suspend", s.handleSuspendUser)
					r.Put("/users/{id}/restore", s.handleRestoreUser)
					r.Put("/users/{id}/archive", s.handleArchiveUser)
					r.Put("/users/{id}/role", s.handleChangeRole)
					r.Post("/users/{id}/invite", s.handleCreateInvitation)
					r.Get("/invitations", s.handleListInvitations)
				})
			})
		})
	})

	if staticFS != nil {
		r.Get("/*", spaHandler(staticFS))
	}

	return r
}

func (s *Server) runPurgeJob() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		n, err := s.db.PurgeTrashedEmails()
		if err != nil {
			slog.Error("purge job failed", "error", err)
		} else if n > 0 {
			slog.Info("purge job completed", "deleted", n)
		}
	}
}

func (s *Server) authRoutes(r chi.Router) {
	r.Use(mid.RateLimit(20, time.Minute))
	r.Get("/setup-status", s.handleSetupStatus)
	r.Post("/setup", s.handleSetup)
	r.Post("/admin-register", s.handleAdminRegister)
	r.Post("/login", s.handleLogin)
	r.Post("/refresh", s.handleRefresh)
	r.With(mid.Auth(s.tokens)).Post("/logout", s.handleLogout)
	r.With(mid.Auth(s.tokens)).Get("/me", s.handleMe)

	// Multi-provider OAuth2 flows.
	r.Get("/{provider}/redirect", s.handleProviderRedirect)
	r.Get("/{provider}/callback", s.handleProviderCallback)

	// Link callback (may arrive unauthenticated — userID is in server-side state).
	r.Get("/{provider}/link/callback", s.handleLinkCallback)

	// Invitation acceptance (public — token is the credential).
	r.Get("/invite/{token}", s.handleInviteValidate)
	r.Post("/invite/{token}/accept", s.handleInviteAccept)

	// Legacy OIDC redirect kept for backward compat.
	r.Get("/oidc/redirect", s.handleOIDCLegacyRedirect)
}

// ---- Auth handlers ----

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.authSvc.SetupStatus()
	if err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	hasUsers, err := s.authSvc.HasUsers()
	if err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	enabled := s.authSvc.EnabledProviders()
	labels := s.authSvc.ProviderLabels()
	jsonOK(w, map[string]interface{}{
		"setup_complete":    cfg.SetupComplete,
		"has_users":         hasUsers,
		"auth_method":       cfg.AuthMethod,
		"oidc_enabled":      s.cfg.OIDCEnabled(),
		"enabled_providers": enabled,
		"provider_labels":   labels,
	})
}

func (s *Server) handleAdminRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "solicitud inválida", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Email == "" || req.Password == "" {
		jsonError(w, "nombre, email y contraseña son obligatorios", http.StatusBadRequest)
		return
	}
	u, access, refresh, familyID, err := s.authSvc.RegisterAdmin(req.Name, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrSetupComplete) {
			jsonError(w, "ya existe un administrador registrado", http.StatusConflict)
			return
		}
		if errors.Is(err, auth.ErrWeakPassword) {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	s.setAuthCookies(w, access, refresh, familyID)
	u.PasswordHash = ""
	jsonOK(w, u)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "solicitud inválida", http.StatusBadRequest)
		return
	}
	if req.Method == "" {
		req.Method = "local"
	}
	if req.Method != "local" && req.Method != "oidc" {
		jsonError(w, "método inválido, use 'local' u 'oidc'", http.StatusBadRequest)
		return
	}
	if req.Method == "oidc" && !s.cfg.OIDCEnabled() {
		jsonError(w, "OIDC no está configurado en este servidor", http.StatusBadRequest)
		return
	}
	if err := s.authSvc.CompleteSetup(req.Method); err != nil {
		if errors.Is(err, auth.ErrSetupComplete) {
			jsonError(w, "la configuración inicial ya fue completada", http.StatusConflict)
			return
		}
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}


func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "solicitud inválida", http.StatusBadRequest)
		return
	}

	u, access, refresh, familyID, err := s.authSvc.LoginLocal(req.Email, req.Password)
	if err != nil {
		jsonError(w, "credenciales inválidas", http.StatusUnauthorized)
		return
	}

	s.setAuthCookies(w, access, refresh, familyID)
	u.PasswordHash = ""
	jsonOK(w, u)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil {
		jsonError(w, "no autorizado", http.StatusUnauthorized)
		return
	}
	familyCookie, err := r.Cookie("family_id")
	if err != nil {
		jsonError(w, "no autorizado", http.StatusUnauthorized)
		return
	}

	newAccess, newRefresh, newFamilyID, err := s.authSvc.RefreshSession(familyCookie.Value, refreshCookie.Value, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, auth.ErrTokenRecentlyRotated) {
			// Refresh concurrente entre pestañas: no es robo, el cliente reintenta.
			w.WriteHeader(http.StatusLocked)
			jsonOK(w, map[string]string{"retry": "recently rotated"})
			return
		}
		// Sesión inválida o expirada: limpiar todo del navegador.
		s.clearAuthCookies(w)
		vlog.Security("refresh_session_failed", "ip", r.RemoteAddr, "error", err.Error())
		jsonError(w, "sesión expirada, inicia sesión nuevamente.", http.StatusUnauthorized)
		return
	}

	s.setAuthCookies(w, newAccess, newRefresh, newFamilyID)
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("family_id"); err == nil {
		_ = s.authSvc.Logout(cookie.Value)
	}
	s.clearAuthCookies(w)
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := mid.GetClaims(r)
	u, err := s.db.GetUserByID(claims.UserID)
	if err != nil {
		jsonError(w, "usuario no encontrado", http.StatusNotFound)
		return
	}
	u.PasswordHash = ""
	jsonOK(w, u)
}

// handleOIDCLegacyRedirect provides backward compatibility for clients still
// using the old /api/auth/oidc/redirect endpoint.
func (s *Server) handleOIDCLegacyRedirect(w http.ResponseWriter, r *http.Request) {
	s.handleProviderRedirectFor(w, r, domain.ProviderOIDC)
}

// handleProviderRedirect reads the provider name from the URL and returns the
// OAuth2 authorization URL.
func (s *Server) handleProviderRedirect(w http.ResponseWriter, r *http.Request) {
	name := domain.ProviderName(chi.URLParam(r, "provider"))
	s.handleProviderRedirectFor(w, r, name)
}

func (s *Server) handleProviderRedirectFor(w http.ResponseWriter, r *http.Request, name domain.ProviderName) {
	authURL, err := s.authSvc.GetProviderRedirect(name)
	if err != nil {
		if errors.Is(err, auth.ErrProviderDisabled) {
			jsonError(w, "proveedor no disponible", http.StatusServiceUnavailable)
			return
		}
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"url": authURL})
}

// handleProviderCallback handles the OAuth2/OIDC callback for login flows.
func (s *Server) handleProviderCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	u, access, refresh, familyID, action, err := s.authSvc.HandleProviderCallback(code, state)
	if err != nil {
		vlog.Security("oauth_callback_failed", "error", err.Error(), "ip", r.RemoteAddr)
		if errors.Is(err, auth.ErrPolicyDenied) {
			http.Redirect(w, r, "/login?error=policy", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/login?error=oauth", http.StatusFound)
		return
	}

	if action == "link" {
		// Link completed — redirect to profile page.
		http.Redirect(w, r, "/profile?linked=true", http.StatusFound)
		return
	}

	s.setAuthCookies(w, access, refresh, familyID)
	_ = u
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLinkCallback handles the OAuth2 callback for account-linking flows.
// The provider callback URL for linking uses the same path as login callbacks
// so the state in server memory distinguishes the two flows.
func (s *Server) handleLinkCallback(w http.ResponseWriter, r *http.Request) {
	s.handleProviderCallback(w, r)
}

// handleLinkStart begins an OAuth2 account-linking flow for the authenticated user.
func (s *Server) handleLinkStart(w http.ResponseWriter, r *http.Request) {
	name := domain.ProviderName(chi.URLParam(r, "provider"))
	userID := mid.GetUserID(r)

	authURL, err := s.authSvc.GetLinkRedirect(name, userID)
	if err != nil {
		if errors.Is(err, auth.ErrProviderDisabled) {
			jsonError(w, "proveedor no disponible", http.StatusServiceUnavailable)
			return
		}
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"url": authURL})
}

// ---- SSE handler ----

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	callerID := mid.GetUserID(r)
	isAdmin := mid.IsAdmin(r)

	projectIDs := make(map[string]struct{})
	if isAdmin {
		projectIDs["*"] = struct{}{}
	} else {
		ids, _ := s.db.GetUserProjects(callerID)
		for _, pid := range ids {
			projectIDs[pid] = struct{}{}
		}
	}

	client := &sseClient{
		userID:     callerID,
		projectIDs: projectIDs,
		ch:         make(chan []byte, 32),
	}
	s.hub.register <- client
	defer func() { s.hub.remove <- client }()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Initial ping to confirm the connection
	fmt.Fprint(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case msg, ok := <-client.ch:
			if !ok {
				return
			}
			w.Write(msg)
			flusher.Flush()
		}
	}
}

// ---- SMTP Relay handlers ----

func (s *Server) handleSMTPStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.db.GetSMTPConfig()
	if err != nil {
		jsonOK(w, map[string]interface{}{"configured": false, "from_address": ""})
		return
	}
	jsonOK(w, map[string]interface{}{"configured": cfg.Enabled, "from_address": cfg.FromAddress})
}

func (s *Server) handleSMTPGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.db.GetSMTPConfig()
	if err != nil {
		jsonOK(w, &domain.SMTPRelayConfig{})
		return
	}
	safe := *cfg
	safe.Password = ""
	if cfg.Password != "" {
		safe.Password = "••••••••"
	}
	jsonOK(w, safe)
}

func (s *Server) handleSMTPSave(w http.ResponseWriter, r *http.Request) {
	var req domain.SMTPRelayConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "solicitud inválida", http.StatusBadRequest)
		return
	}
	if req.Host == "" || req.Port == 0 || req.FromAddress == "" {
		jsonError(w, "host, puerto y dirección de envío son requeridos", http.StatusBadRequest)
		return
	}

	existing, err := s.db.GetSMTPConfig()
	if err == nil && req.Password == "••••••••" {
		req.Password = existing.Password
	}

	if err := s.db.SaveSMTPConfig(&req); err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	safe := req
	safe.Password = ""
	if req.Password != "" {
		safe.Password = "••••••••"
	}
	jsonOK(w, safe)
}

func (s *Server) handleSMTPTest(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.db.GetSMTPConfig()
	if err != nil {
		jsonError(w, "smtp no configurado", http.StatusBadRequest)
		return
	}
	if err := smtprelay.TestConnection(cfg); err != nil {
		slog.Warn("smtp relay test failed", "error", err.Error())
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// ---- Relay addresses handlers ----

func (s *Server) handleRelayAddressList(w http.ResponseWriter, r *http.Request) {
	userID := mid.GetUserID(r)
	addrs, err := s.db.GetRelayAddresses(userID)
	if err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	if addrs == nil {
		addrs = []string{}
	}
	jsonOK(w, addrs)
}

func (s *Server) handleRelayAddressAdd(w http.ResponseWriter, r *http.Request) {
	userID := mid.GetUserID(r)
	var req struct {
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Addr == "" {
		jsonError(w, "dirección inválida", http.StatusBadRequest)
		return
	}
	if err := s.db.AddRelayAddress(userID, req.Addr); err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	addrs, _ := s.db.GetRelayAddresses(userID)
	if addrs == nil {
		addrs = []string{}
	}
	jsonOK(w, addrs)
}

func (s *Server) handleRelayAddressDelete(w http.ResponseWriter, r *http.Request) {
	userID := mid.GetUserID(r)
	var req struct {
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Addr == "" {
		jsonError(w, "dirección inválida", http.StatusBadRequest)
		return
	}
	if err := s.db.DeleteRelayAddress(userID, req.Addr); err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	addrs, _ := s.db.GetRelayAddresses(userID)
	if addrs == nil {
		addrs = []string{}
	}
	jsonOK(w, addrs)
}

// ---- Cookie helpers ----

func (s *Server) setAuthCookies(w http.ResponseWriter, access, refresh, familyID string) {
	secure := strings.HasPrefix(s.cfg.BaseURL, "https://")

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    access,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   15 * 60,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refresh,
		Path:     "/api/auth/refresh",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "family_id",
		Value:    familyID,
		Path:     "/api/auth",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60,
	})
}

func (s *Server) clearAuthCookies(w http.ResponseWriter) {
	for _, name := range []string{"access_token", "refresh_token", "family_id"} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
	}
}

// ---- Response helpers ----

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---- Invitation handlers ----

func (s *Server) handleInviteValidate(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	inv, err := s.authSvc.ValidateInvitation(token)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvitationNotFound):
			jsonError(w, "invitación no encontrada", http.StatusNotFound)
		case errors.Is(err, auth.ErrInvitationExpired):
			jsonError(w, "la invitación ha expirado", http.StatusGone)
		case errors.Is(err, auth.ErrInvitationUsed):
			jsonError(w, "la invitación ya fue utilizada", http.StatusConflict)
		default:
			jsonError(w, "error interno", http.StatusInternalServerError)
		}
		return
	}
	u, _ := s.db.GetUserByID(inv.UserID)
	jsonOK(w, map[string]interface{}{
		"valid":      true,
		"user_email": u.Email,
		"user_name":  u.Name,
		"expires_at": inv.ExpiresAt,
	})
}

func (s *Server) handleInviteAccept(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		jsonError(w, "contraseña requerida", http.StatusBadRequest)
		return
	}

	u, err := s.authSvc.AcceptInvitation(token, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvitationNotFound):
			jsonError(w, "invitación no encontrada", http.StatusNotFound)
		case errors.Is(err, auth.ErrInvitationExpired):
			jsonError(w, "la invitación ha expirado", http.StatusGone)
		case errors.Is(err, auth.ErrInvitationUsed):
			jsonError(w, "la invitación ya fue utilizada", http.StatusConflict)
		case errors.Is(err, auth.ErrWeakPassword):
			jsonError(w, "la contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número", http.StatusBadRequest)
		default:
			jsonError(w, "error interno", http.StatusInternalServerError)
		}
		return
	}

	access, refresh, familyID, err := s.tokens.IssueTokens(u.ID, u.Role)
	if err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	s.setAuthCookies(w, access, refresh, familyID)
	u.PasswordHash = ""
	jsonOK(w, u)
}

// ---- Profile / account linking handlers ----

func (s *Server) handleListMyProviders(w http.ResponseWriter, r *http.Request) {
	userID := mid.GetUserID(r)
	providers, err := s.authSvc.ListUserProviders(userID)
	if err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	jsonOK(w, providers)
}

func (s *Server) handleUnlinkProvider(w http.ResponseWriter, r *http.Request) {
	userID := mid.GetUserID(r)
	name := domain.ProviderName(chi.URLParam(r, "provider"))

	if err := s.authSvc.UnlinkProvider(userID, name); err != nil {
		switch {
		case errors.Is(err, auth.ErrLastProvider):
			jsonError(w, "no puedes eliminar tu único método de acceso. Vincula otro proveedor primero.", http.StatusBadRequest)
		case errors.Is(err, storage.ErrNotFound):
			jsonError(w, "proveedor no vinculado", http.StatusNotFound)
		default:
			jsonError(w, "error interno", http.StatusInternalServerError)
		}
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := mid.GetUserID(r)
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "solicitud inválida", http.StatusBadRequest)
		return
	}
	if req.OldPassword == "" || req.NewPassword == "" {
		jsonError(w, "contraseña antigua y nueva son requeridas", http.StatusBadRequest)
		return
	}
	if err := s.authSvc.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidAuth):
			jsonError(w, "contraseña actual incorrecta", http.StatusUnauthorized)
		case errors.Is(err, auth.ErrWeakPassword):
			jsonError(w, "la nueva contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número", http.StatusBadRequest)
		default:
			jsonError(w, "error interno", http.StatusInternalServerError)
		}
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// ---- Admin: provider config handlers ----

func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request) {
	cfgs, err := s.authSvc.ListProviderConfigs()
	if err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	// Mask secrets in response.
	for i := range cfgs {
		if cfgs[i].ClientSecret != "" {
			cfgs[i].ClientSecret = "••••••••"
		}
	}
	jsonOK(w, cfgs)
}

func (s *Server) handleSaveProvider(w http.ResponseWriter, r *http.Request) {
	name := domain.ProviderName(chi.URLParam(r, "name"))
	callerID := mid.GetUserID(r)

	var req domain.AuthProviderConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "solicitud inválida", http.StatusBadRequest)
		return
	}
	req.Name = name

	// If the secret was sent back masked, keep the existing one.
	if req.ClientSecret == "••••••••" {
		existing, err := s.db.GetAuthProviderConfig(name)
		if err == nil {
			req.ClientSecret = existing.ClientSecret
		}
	}
	if req.Policies == nil {
		req.Policies = []domain.AccessPolicy{}
	}

	if err := s.authSvc.SaveProviderConfig(&req, callerID); err != nil {
		switch {
		case errors.Is(err, auth.ErrLastEnabledProvider):
			jsonError(w, "debe quedar al menos un método de autenticación habilitado.", http.StatusBadRequest)
		case errors.Is(err, auth.ErrLastProvider):
			jsonError(w, "no puedes deshabilitar tu único método de acceso. Vincula otro proveedor primero desde Mi Perfil.", http.StatusBadRequest)
		default:
			jsonError(w, "error interno", http.StatusInternalServerError)
		}
		return
	}
	resp := req
	if resp.ClientSecret != "" {
		resp.ClientSecret = "••••••••"
	}
	jsonOK(w, resp)
}

// ---- Admin: user management handlers ----

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Name == "" {
		jsonError(w, "email y nombre son requeridos", http.StatusBadRequest)
		return
	}

	u, err := s.authSvc.CreatePendingUser(req.Email, req.Name)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	inv, err := s.authSvc.CreateInvitation(u.ID)
	if err != nil {
		jsonError(w, "usuario creado pero no se pudo generar la invitación", http.StatusInternalServerError)
		return
	}

	invURL := s.cfg.BaseURL + "/invite/" + inv.Token
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]interface{}{
		"user":           u,
		"invitation_url": invURL,
		"expires_at":     inv.ExpiresAt,
	})
}

func (s *Server) handleSuspendUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	callerID := mid.GetUserID(r)
	if id == callerID {
		jsonError(w, "no puedes suspenderte a ti mismo", http.StatusBadRequest)
		return
	}
	if err := s.authSvc.SuspendUser(id); err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleRestoreUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.authSvc.RestoreUser(id); err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleArchiveUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	callerID := mid.GetUserID(r)
	if id == callerID {
		jsonError(w, "no puedes archivar tu propio usuario", http.StatusBadRequest)
		return
	}
	if err := s.authSvc.ArchiveUser(id); err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleChangeRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	callerID := mid.GetUserID(r)
	if id == callerID {
		jsonError(w, "no puedes cambiar tu propio rol", http.StatusBadRequest)
		return
	}
	var req struct {
		Role domain.Role `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "solicitud inválida", http.StatusBadRequest)
		return
	}
	if req.Role != domain.RoleAdmin && req.Role != domain.RoleUser {
		jsonError(w, "rol inválido", http.StatusBadRequest)
		return
	}
	u, err := s.db.GetUserByID(id)
	if err != nil {
		jsonError(w, "usuario no encontrado", http.StatusNotFound)
		return
	}
	u.Role = req.Role
	if err := s.db.UpdateUser(u); err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleCreateInvitation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	inv, err := s.authSvc.CreateInvitation(id)
	if err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}
	invURL := s.cfg.BaseURL + "/invite/" + inv.Token
	jsonOK(w, map[string]interface{}{
		"invitation_url": invURL,
		"expires_at":     inv.ExpiresAt,
	})
}

func (s *Server) handleListInvitations(w http.ResponseWriter, r *http.Request) {
	invs, err := s.authSvc.ListInvitations()
	if err != nil {
		jsonError(w, "error interno", http.StatusInternalServerError)
		return
	}

	type invResponse struct {
		domain.Invitation
		InvitationURL string `json:"invitation_url"`
		UserEmail     string `json:"user_email"`
		UserName      string `json:"user_name"`
		Status        string `json:"status"`
	}

	result := make([]invResponse, 0, len(invs))
	for _, inv := range invs {
		r := invResponse{Invitation: inv}
		if u, err := s.db.GetUserByID(inv.UserID); err == nil {
			r.UserEmail = u.Email
			r.UserName = u.Name
		}
		switch {
		case inv.UsedAt != nil:
			r.Status = "used"
		case inv.ExpiresAt.Before(time.Now()):
			r.Status = "expired"
		default:
			r.Status = "pending"
			r.InvitationURL = s.cfg.BaseURL + "/invite/" + inv.Token
		}
		result = append(result, r)
	}
	jsonOK(w, result)
}

// spaHandler serves the embedded SPA frontend, falling back to index.html for
// client-side routes.
func spaHandler(fsys fs.FS) http.HandlerFunc {
	server := http.FileServer(http.FS(fsys))
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "."
		}
		if _, err := fsys.Open(path); err != nil {
			data, err := fs.ReadFile(fsys, "index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
			return
		}
		server.ServeHTTP(w, r)
	}
}

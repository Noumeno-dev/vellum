import { useAuthStore } from '@/store/auth'

export type ProviderName = 'local' | 'github' | 'google' | 'discord' | 'oidc'
export type UserStatus = 'pending' | 'active' | 'suspended' | 'archived'

/** Registered user within the Vellum platform. */
export interface User {
  id: string
  email: string
  name: string
  role: 'admin' | 'user'
  status: UserStatus
  /** @deprecated use status instead */
  active?: boolean
  /** @deprecated use linked providers instead */
  provider?: ProviderName
  created_at: string
  updated_at: string
}

/** An external identity linked to a user account. */
export interface ProviderIdentity {
  id: string
  user_id: string
  provider: ProviderName
  provider_id: string
  email: string
  username?: string
  linked_at: string
}

export type AccessPolicyType = 'email' | 'username' | 'id' | 'sub'

export interface AccessPolicy {
  id: string
  type: AccessPolicyType
  value: string
}

/** Configuration for one authentication provider. */
export interface AuthProviderConfig {
  name: ProviderName
  enabled: boolean
  display_name?: string
  client_id?: string
  client_secret?: string
  issuer_url?: string
  policies: AccessPolicy[]
}

/** An invitation to create a local account. */
export interface Invitation {
  id: string
  user_id: string
  token: string
  expires_at: string
  used_at?: string
  renewed_at?: string
  created_at: string
  /** Derived by the server: 'pending' | 'expired' | 'used' */
  status: 'pending' | 'expired' | 'used'
  invitation_url?: string
  user_email?: string
  user_name?: string
}

/** Response from creating a new pending user. */
export interface CreateUserResponse {
  user: User
  invitation_url: string
  expires_at: string
}

/** Response from renewing an invitation. */
export interface RenewInvitationResponse {
  invitation_url: string
  expires_at: string
}

/** Organizational unit that groups incoming emails by sender address. */
export interface Project {
  id: string
  name: string
  description: string
  /** Sender addresses that route inbound emails into this project. */
  senders: string[]
  active: boolean
  /** Maximum storage in bytes. Zero means unlimited. */
  storage_limit: number
  created_at: string
  updated_at: string
  deleted_at?: string
}

/** Current storage consumption against the configured limit for a project. */
export interface ProjectStorageUsage {
  used_bytes: number
  limit_bytes: number
}

/** Association between a project and an authorized user. */
export interface ProjectMember {
  project_id: string
  user_id: string
  added_at: string
}

/** Binary attachment metadata embedded in an email. */
export interface Attachment {
  id: string
  filename: string
  content_type: string
  size: number
}

/** Inbound email captured by the SMTP server. */
export interface Email {
  id: string
  project_id: string
  message_id: string
  from: string
  to: string[]
  cc: string[]
  subject: string
  text_body: string
  html_body: string
  attachments: Attachment[]
  received_at: string
  /** User IDs that have marked this email as read. */
  read_by: string[]
  size: number
  /** Spam probability score assigned by Vellum Sentinel. */
  spam_score: number
  /** Original MIME headers indexed by lowercase key. */
  raw_headers?: Record<string, string[]>
  deleted_at?: string
  /** Timestamp after which the email will be permanently removed. */
  purge_at?: string
  /** Indicates the parent project has been soft-deleted. */
  project_deleted?: boolean
}

/** Pagination metadata returned by list endpoints. */
export interface PageMeta {
  page: number
  page_size: number
  total: number
}

/** Envelope for paginated API responses. */
export interface PaginatedResponse<T> {
  data: T[]
  meta: PageMeta
}

/** Single verification check within an email analysis category. */
export interface AnalysisCheck {
  id: string
  name: string
  passed: boolean
  skipped: boolean
  severity: 'blocker' | 'critical' | 'warning' | 'info'
  detail: string
  /** Points deducted from the overall score when the check fails. */
  impact: number
}

/** Logical grouping of related analysis checks (e.g., "Security", "Deliverability"). */
export interface AnalysisCategory {
  id: string
  name: string
  passed: number
  total: number
  checks: AnalysisCheck[]
}

/**
 * Complete structural analysis result for an email.
 * Produced by the server-side analyzer engine.
 */
export interface EmailAnalysis {
  /** Numeric score from 0 to 100. */
  score: number
  /** Letter grade derived from the score (A+, A, B, C, D, F). */
  grade: string
  summary: string
  /** Whether the email satisfies all RFC and security requirements for the Vellum Verified badge. */
  is_vellum_verified: boolean
  verification_disclaimer: string
  categories: AnalysisCategory[]
}

/** Initial setup status returned before the first user is registered. */
export interface SetupStatus {
  setup_complete: boolean
  has_users: boolean
  auth_method: string
  oidc_enabled: boolean
  enabled_providers: ProviderName[]
  provider_labels?: Record<ProviderName, string>
}

/** SMTP relay server configuration managed by administrators. */
export interface SMTPConfig {
  host: string
  port: number
  username: string
  password: string
  from_address: string
  use_tls: boolean
  enabled: boolean
}

/** Abbreviated SMTP relay status for non-admin consumers. */
export interface SMTPStatus {
  configured: boolean
  from_address: string
}

let isRefreshing = false
let refreshQueue: Array<() => void> = []

/**
 * Attempts to refresh the authentication token via the server cookie.
 * Concurrent calls are coalesced into a single network request; subsequent
 * callers wait on a shared promise that resolves once the first request completes.
 */
async function tryRefresh(): Promise<boolean> {
  if (isRefreshing) {
    return new Promise((resolve) => {
      refreshQueue.push(() => resolve(true))
    })
  }
  isRefreshing = true
  try {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'include',
    })
    refreshQueue.forEach((fn) => fn())
    refreshQueue = []
    return res.ok
  } finally {
    isRefreshing = false
  }
}

/**
 * Removes all Vellum-scoped data from localStorage and sessionStorage.
 * Invoked after an unrecoverable authentication failure.
 */
function clearBrowserData() {
  useAuthStore.getState().clear()
  Object.keys(localStorage).forEach((k) => {
    if (k.startsWith('vellum-')) localStorage.removeItem(k)
  })
  sessionStorage.clear()
}

/**
 * Central HTTP wrapper for all API calls.
 *
 * Automatically prepends `/api`, includes credentials, and handles:
 * - **423 (Locked):** Concurrent token rotation across tabs; retries after a short delay.
 * - **401 (Unauthorized):** Triggers a token refresh. On failure, clears session and redirects to login.
 * - **204 (No Content):** Returns `undefined` cast to `T`.
 *
 * @typeParam T - Expected JSON response shape.
 * @param url - Path relative to `/api` (e.g., `/auth/me`).
 * @param init - Standard `RequestInit` overrides.
 */
async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch('/api' + url, {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
  })

  // Token rotado concurrentemente entre pestañas: reintentar con las cookies actuales.
  if (res.status === 423) {
    await new Promise((r) => setTimeout(r, 150))
    return request<T>(url, init)
  }

  if (res.status === 401 && !url.startsWith('/auth/')) {
    const ok = await tryRefresh()
    if (ok) {
      return request<T>(url, init)
    }
    clearBrowserData()
    window.location.href = '/login'
    throw new Error('no autorizado')
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: 'Error desconocido.' }))
    throw new Error(body.error ?? 'Error desconocido.')
  }

  if (res.status === 204) return undefined as T
  return res.json() as T
}

/**
 * Multipart variant of {@link request} used for file uploads.
 * Does not set `Content-Type` so the browser can attach the multipart boundary.
 *
 * @typeParam T - Expected JSON response shape.
 * @param url - Path relative to `/api`.
 * @param formData - Prepared `FormData` payload.
 * @param query - Optional query string appended to the URL.
 */
async function requestMultipart<T>(url: string, formData: FormData, query?: string): Promise<T> {
  const fullUrl = '/api' + url + (query ? '?' + query : '')
  const res = await fetch(fullUrl, {
    method: 'POST',
    credentials: 'include',
    body: formData,
  })

  if (res.status === 423) {
    await new Promise((r) => setTimeout(r, 150))
    return requestMultipart<T>(url, formData, query)
  }

  if (res.status === 401) {
    const ok = await tryRefresh()
    if (ok) return requestMultipart<T>(url, formData, query)
    clearBrowserData()
    window.location.href = '/login'
    throw new Error('no autorizado')
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: 'Error desconocido.' }))
    throw new Error(body.error ?? 'Error desconocido.')
  }

  return res.json() as T
}

/**
 * Typed facade that organizes every backend endpoint into logical namespaces.
 * All methods return promises and delegate to {@link request} or {@link requestMultipart}.
 */
export const api = {
  auth: {
    setupStatus: () => request<SetupStatus>('/auth/setup-status'),
    setup: (method: 'local' | 'oidc') => request<{ ok: boolean }>('/auth/setup', { method: 'POST', body: JSON.stringify({ method }) }),
    registerAdmin: (name: string, email: string, password: string) =>
      request<User>('/auth/admin-register', { method: 'POST', body: JSON.stringify({ name, email, password }) }),
    login: (email: string, password: string) =>
      request<User>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
    refresh: () => request<{ ok: boolean }>('/auth/refresh', { method: 'POST' }),
    logout: () => request<{ ok: boolean }>('/auth/logout', { method: 'POST' }),
    me: () => request<User>('/auth/me'),
    providerRedirect: (provider: ProviderName) =>
      request<{ url: string }>(`/auth/${provider}/redirect`),
    linkStart: (provider: ProviderName) =>
      request<{ url: string }>(`/auth/${provider}/link/start`),
    validateInvite: (token: string) =>
      request<{ valid: boolean; user_email: string; user_name: string; expires_at: string }>(`/auth/invite/${token}`),
    acceptInvite: (token: string, password: string) =>
      request<User>(`/auth/invite/${token}/accept`, { method: 'POST', body: JSON.stringify({ password }) }),
    changePassword: (oldPassword: string, newPassword: string) =>
      request<{ ok: boolean }>('/me/password', { method: 'POST', body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }) }),
  },

  me: {
    providers: () => request<ProviderIdentity[]>('/me/providers'),
    unlinkProvider: (provider: ProviderName) =>
      request<{ ok: boolean }>(`/me/providers/${provider}`, { method: 'DELETE' }),
  },

  users: {
    list: () => request<User[]>('/users'),
    get: (id: string) => request<User>(`/users/${id}`),
    update: (id: string, data: { name?: string }) =>
      request<User>(`/users/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  },

  admin: {
    createUser: (email: string, name: string) =>
      request<CreateUserResponse>('/admin/users', { method: 'POST', body: JSON.stringify({ email, name }) }),
    suspendUser: (id: string) =>
      request<{ ok: boolean }>(`/admin/users/${id}/suspend`, { method: 'PUT' }),
    restoreUser: (id: string) =>
      request<{ ok: boolean }>(`/admin/users/${id}/restore`, { method: 'PUT' }),
    archiveUser: (id: string) =>
      request<{ ok: boolean }>(`/admin/users/${id}/archive`, { method: 'PUT' }),
    changeRole: (id: string, role: 'admin' | 'user') =>
      request<{ ok: boolean }>(`/admin/users/${id}/role`, { method: 'PUT', body: JSON.stringify({ role }) }),
    createInvitation: (userId: string) =>
      request<RenewInvitationResponse>(`/admin/users/${userId}/invite`, { method: 'POST' }),
    listInvitations: () => request<Invitation[]>('/admin/invitations'),
    listProviders: () => request<AuthProviderConfig[]>('/admin/auth/providers'),
    saveProvider: (name: ProviderName, cfg: AuthProviderConfig) =>
      request<AuthProviderConfig>(`/admin/auth/providers/${name}`, { method: 'PUT', body: JSON.stringify(cfg) }),
  },

  projects: {
    list: () => request<Project[]>('/projects'),
    unreadCounts: () => request<Record<string, number>>('/projects/unread-counts'),
    storageUsages: () => request<Record<string, ProjectStorageUsage>>('/admin/projects/storage-usages'),
    storage: (id: string) => request<ProjectStorageUsage>(`/projects/${id}/storage`),
    create: (data: { name: string; description: string; senders: string[]; storage_limit: number }) =>
      request<Project>('/projects', { method: 'POST', body: JSON.stringify(data) }),
    get: (id: string) => request<Project>(`/projects/${id}`),
    update: (id: string, data: Partial<Project>) =>
      request<Project>(`/projects/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    delete: (id: string) => request<void>(`/projects/${id}`, { method: 'DELETE' }),
    listMembers: (id: string) => request<ProjectMember[]>(`/projects/${id}/members`),
    addMember: (id: string, userId: string) =>
      request<ProjectMember>(`/projects/${id}/members`, { method: 'POST', body: JSON.stringify({ user_id: userId }) }),
    removeMember: (id: string, userId: string) =>
      request<void>(`/projects/${id}/members/${userId}`, { method: 'DELETE' }),
  },

  emails: {
    list: (projectId: string, page = 1, pageSize = 50) =>
      request<PaginatedResponse<Email>>(`/projects/${projectId}/emails?page=${page}&page_size=${pageSize}`),
    get: (projectId: string, emailId: string) =>
      request<Email>(`/projects/${projectId}/emails/${emailId}`),
    delete: (projectId: string, emailId: string) =>
      request<void>(`/projects/${projectId}/emails/${emailId}`, { method: 'DELETE' }),
    markRead: (projectId: string, emailId: string) =>
      request<{ ok: boolean }>(`/projects/${projectId}/emails/${emailId}/read`, { method: 'POST' }),
    analyze: (projectId: string, emailId: string, lang = 'es') =>
      request<EmailAnalysis>(`/projects/${projectId}/emails/${emailId}/analysis?lang=${lang}`),
    relay: (projectId: string, emailId: string, to: string[]) =>
      request<{ ok: boolean }>(`/projects/${projectId}/emails/${emailId}/relay`, {
        method: 'POST',
        body: JSON.stringify({ to }),
      }),
    listAll: (page = 1, pageSize = 50) =>
      request<PaginatedResponse<Email>>(`/admin/emails?page=${page}&page_size=${pageSize}`),
    deleteAny: (emailId: string) =>
      request<void>(`/admin/emails/${emailId}`, { method: 'DELETE' }),
    deleteAllByProject: (projectId: string) =>
      request<{ deleted: number }>(`/admin/projects/${projectId}/emails`, { method: 'DELETE' }),
  },

  smtp: {
    status: () => request<SMTPStatus>('/smtp/status'),
    get: () => request<SMTPConfig>('/admin/smtp'),
    save: (cfg: SMTPConfig) =>
      request<SMTPConfig>('/admin/smtp', { method: 'PUT', body: JSON.stringify(cfg) }),
    test: () => request<{ ok: boolean }>('/admin/smtp/test', { method: 'POST' }),
  },

  relayAddresses: {
    list: () => request<string[]>('/relay-addresses'),
    add: (addr: string) =>
      request<string[]>('/relay-addresses', { method: 'POST', body: JSON.stringify({ addr }) }),
    remove: (addr: string) =>
      request<string[]>('/relay-addresses', { method: 'DELETE', body: JSON.stringify({ addr }) }),
  },

  trash: {
    list: (projectId: string, page = 1, pageSize = 50) =>
      request<PaginatedResponse<Email>>(`/projects/${projectId}/emails/trash?page=${page}&page_size=${pageSize}`),
    stats: (projectId: string) =>
      request<{ total: number; size_bytes: number }>(`/projects/${projectId}/emails/trash/stats`),
    restore: (projectId: string, ids: string[]) =>
      request<void>(`/projects/${projectId}/emails/trash/restore`, { method: 'POST', body: JSON.stringify({ ids }) }),
    deleteOne: (projectId: string, emailId: string) =>
      request<void>(`/projects/${projectId}/emails/trash/${emailId}`, { method: 'DELETE' }),
    purge: (projectId: string) =>
      request<void>(`/projects/${projectId}/emails/trash`, { method: 'DELETE' }),
  },

  adminTrash: {
    listProjects: () => request<Project[]>('/admin/projects/trash'),
    restoreProject: (id: string) => request<Project>(`/admin/projects/${id}/restore`, { method: 'POST' }),
    purgeProject: (id: string) => request<void>(`/admin/projects/${id}/purge`, { method: 'DELETE' }),
  },

  analyzer: {
    analyzeHtml: (file: File, lang = 'es'): Promise<EmailAnalysis> => {
      const form = new FormData()
      form.append('html', file)
      return requestMultipart<EmailAnalysis>('/analyzer', form, `lang=${lang}`)
    },
  },
}

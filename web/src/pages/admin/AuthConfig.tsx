import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, ChevronDown, ChevronRight, Github, Chrome, MessageSquare, ShieldCheck, Lock, Save, Copy } from 'lucide-react'
import { api } from '@/lib/api'
import type { AuthProviderConfig, ProviderName, AccessPolicy, AccessPolicyType } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import { useI18n } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useToast } from '@/hooks/use-toast'

const ALL_PROVIDERS: ProviderName[] = ['local', 'github', 'google', 'discord', 'oidc']

const providerIcons: Record<ProviderName, React.ReactNode> = {
  local: <Lock className="h-4 w-4" />,
  github: <Github className="h-4 w-4" />,
  google: <Chrome className="h-4 w-4" />,
  discord: <MessageSquare className="h-4 w-4" />,
  oidc: <ShieldCheck className="h-4 w-4" />,
}

function Switch({ checked, onCheckedChange, id }: { checked: boolean; onCheckedChange: (v: boolean) => void; id?: string }) {
  return (
    <button
      id={id}
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onCheckedChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ring ${checked ? 'bg-primary' : 'bg-input'}`}
    >
      <span
        className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-background shadow-lg transition-transform ${checked ? 'translate-x-4' : 'translate-x-0'}`}
      />
    </button>
  )
}

const POLICY_TYPES: { value: AccessPolicyType; label: string }[] = [
  { value: 'email', label: 'Email' },
  { value: 'username', label: 'Username / login' },
  { value: 'id', label: 'Numeric ID' },
  { value: 'sub', label: 'Subject (OIDC sub)' },
]

function ProviderCard({
  name,
  initial,
}: {
  name: ProviderName
  initial?: AuthProviderConfig
}) {
  const t = useI18n()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const currentUser = useAuthStore((s) => s.user)

  const defaultCfg: AuthProviderConfig = initial ?? {
    name,
    enabled: false,
    client_id: '',
    client_secret: '',
    issuer_url: '',
    policies: [],
  }

  const [cfg, setCfg] = useState<AuthProviderConfig>(defaultCfg)
  const [expanded, setExpanded] = useState(false)
  const [newPolicyType, setNewPolicyType] = useState<AccessPolicyType>('email')
  const [newPolicyValue, setNewPolicyValue] = useState('')

  const saveMutation = useMutation({
    mutationFn: () => api.admin.saveProvider(name, cfg),
    onSuccess: (saved) => {
      setCfg(saved)
      queryClient.invalidateQueries({ queryKey: ['admin-providers'] })
      queryClient.invalidateQueries({ queryKey: ['setup-status'] })
      toast({ title: t.adminAuth.saved })
    },
    onError: (err: Error) => toast({ title: err.message, variant: 'destructive' }),
  })

  function addPolicy() {
    if (!newPolicyValue.trim()) return
    const policy: AccessPolicy = {
      id: crypto.randomUUID(),
      type: newPolicyType,
      value: newPolicyValue.trim(),
    }
    setCfg((prev) => ({ ...prev, policies: [...(prev.policies ?? []), policy] }))
    setNewPolicyValue('')
  }

  function removePolicy(id: string) {
    setCfg((prev) => ({ ...prev, policies: prev.policies.filter((p) => p.id !== id) }))
  }

  const needsCredentials = name !== 'local'

  return (
    <div className="rounded-lg border bg-card overflow-hidden">
      <div className="flex items-center gap-3 p-4">
        <span className="text-muted-foreground">{providerIcons[name]}</span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium">{providerLabel(name, t)}</p>
          <p className="text-xs text-muted-foreground">{providerDesc(name, t)}</p>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant={cfg.enabled ? 'default' : 'secondary'} className="text-xs">
            {cfg.enabled ? t.adminAuth.enabled : t.adminAuth.disabled}
          </Badge>
          <Switch
            checked={cfg.enabled}
            onCheckedChange={(v) => setCfg((prev) => ({ ...prev, enabled: v }))}
          />
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </Button>
        </div>
      </div>

      {expanded && (
        <div className="border-t p-4 space-y-4">
          {needsCredentials && (
            <>
              {/* Callback URL — must be registered in the provider */}
              <div className="space-y-1.5">
                <p className="text-xs font-semibold">{t.adminAuth.callbackUrl}</p>
                <p className="text-xs text-muted-foreground">{t.adminAuth.callbackUrlDesc}</p>
                <div className="flex items-center gap-2 bg-muted rounded-md px-3 py-2">
                  <span className="flex-1 font-mono text-xs break-all select-all">
                    {`${window.location.origin}/api/auth/${name}/callback`}
                  </span>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 shrink-0"
                    onClick={() => {
                      navigator.clipboard.writeText(`${window.location.origin}/api/auth/${name}/callback`)
                      toast({ title: t.adminAuth.copied })
                    }}
                  >
                    <Copy className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
              <Separator />
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label className="text-xs">{t.adminAuth.clientId}</Label>
                  <Input
                    value={cfg.client_id ?? ''}
                    onChange={(e) => setCfg((prev) => ({ ...prev, client_id: e.target.value }))}
                    placeholder="client_id"
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">{t.adminAuth.clientSecret}</Label>
                  <Input
                    type="password"
                    value={cfg.client_secret ?? ''}
                    onChange={(e) => setCfg((prev) => ({ ...prev, client_secret: e.target.value }))}
                    placeholder="client_secret"
                  />
                </div>
                {name === 'oidc' && (
                  <>
                    <div className="space-y-1 sm:col-span-2">
                      <Label className="text-xs">{t.adminAuth.issuerUrl}</Label>
                      <Input
                        value={cfg.issuer_url ?? ''}
                        onChange={(e) => setCfg((prev) => ({ ...prev, issuer_url: e.target.value }))}
                        placeholder="https://your-provider.com"
                      />
                    </div>
                    <div className="space-y-1 sm:col-span-2">
                      <Label className="text-xs">Nombre personalizado en botón (opcional)</Label>
                      <Input
                        value={cfg.display_name ?? ''}
                        onChange={(e) => setCfg((prev) => ({ ...prev, display_name: e.target.value }))}
                        placeholder="Ej. Mi Empresa"
                      />
                    </div>
                  </>
                )}
              </div>
              <Separator />
            </>
          )}

          {/* Access policies */}
          <div className="space-y-2">
            <div>
              <p className="text-xs font-semibold">{t.adminAuth.policies}</p>
              <p className="text-xs text-muted-foreground">{t.adminAuth.policiesDesc}</p>
            </div>

            {(cfg.policies ?? []).map((p) => (
              <div key={p.id} className="flex items-center gap-2 text-xs bg-muted rounded-md px-2 py-1.5">
                <Badge variant="outline" className="text-xs">{p.type}</Badge>
                <span className="flex-1 font-mono">{p.value}</span>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-5 w-5 text-muted-foreground hover:text-destructive"
                  onClick={() => removePolicy(p.id)}
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            ))}

            <div className="flex gap-2">
              <select
                value={newPolicyType}
                onChange={(e) => setNewPolicyType(e.target.value as AccessPolicyType)}
                className="flex h-9 rounded-md border border-input bg-background px-2 text-xs focus:outline-none"
              >
                {POLICY_TYPES.map((pt) => (
                  <option key={pt.value} value={pt.value}>{pt.label}</option>
                ))}
              </select>
              <Input
                className="flex-1 text-xs h-9"
                value={newPolicyValue}
                onChange={(e) => setNewPolicyValue(e.target.value)}
                placeholder={newPolicyType === 'email' ? 'user@empresa.com o @empresa.com' : 'valor'}
                onKeyDown={(e) => e.key === 'Enter' && addPolicy()}
              />
              <Button variant="outline" size="icon" className="h-9 w-9 shrink-0" onClick={addPolicy}>
                <Plus className="h-4 w-4" />
              </Button>
            </div>
          </div>

          <div className="flex justify-end">
            <Button
              size="sm"
              onClick={() => saveMutation.mutate()}
              disabled={saveMutation.isPending}
            >
              <Save className="h-3.5 w-3.5 mr-1.5" />
              {saveMutation.isPending ? t.adminAuth.saving : t.adminAuth.save}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

function providerLabel(name: ProviderName, t: ReturnType<typeof useI18n>): string {
  const map: Record<ProviderName, string> = {
    local: t.adminAuth.providerLocal,
    github: t.adminAuth.providerGitHub,
    google: t.adminAuth.providerGoogle,
    discord: t.adminAuth.providerDiscord,
    oidc: t.adminAuth.providerOIDC,
  }
  return map[name]
}

function providerDesc(name: ProviderName, t: ReturnType<typeof useI18n>): string {
  const map: Record<ProviderName, string> = {
    local: t.adminAuth.providerLocalDesc,
    github: t.adminAuth.providerGithubDesc,
    google: t.adminAuth.providerGoogleDesc,
    discord: t.adminAuth.providerDiscordDesc,
    oidc: t.adminAuth.providerOidcDesc,
  }
  return map[name]
}

export default function AdminAuthPage() {
  const t = useI18n()

  const { data: configs = [], isLoading } = useQuery({
    queryKey: ['admin-providers'],
    queryFn: api.admin.listProviders,
  })

  const configMap = Object.fromEntries(configs.map((c) => [c.name, c])) as Partial<Record<ProviderName, AuthProviderConfig>>

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center px-6 h-14 border-b shrink-0">
        <div>
          <h1 className="text-base font-semibold">{t.adminAuth.title}</h1>
          <p className="text-xs text-muted-foreground">{t.adminAuth.subtitle}</p>
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-6 max-w-2xl space-y-3">
          {isLoading
            ? <p className="text-sm text-muted-foreground">{t.adminAuth.loading}</p>
            : ALL_PROVIDERS.map((name) => (
                <ProviderCard key={name} name={name} initial={configMap[name]} />
              ))
          }
        </div>
      </ScrollArea>
    </div>
  )
}

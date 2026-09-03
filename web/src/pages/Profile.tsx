import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link2, Link2Off, KeyRound, Github, Chrome, MessageSquare, ShieldCheck, Lock } from 'lucide-react'
import { api } from '@/lib/api'
import type { ProviderName } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import { useI18n } from '@/lib/i18n'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'
import { useToast } from '@/hooks/use-toast'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'

const providerIcons: Record<ProviderName, React.ReactNode> = {
  local: <Lock className="h-4 w-4" />,
  github: <Github className="h-4 w-4" />,
  google: <Chrome className="h-4 w-4" />,
  discord: <MessageSquare className="h-4 w-4" />,
  oidc: <ShieldCheck className="h-4 w-4" />,
}

const providerLabels: Record<ProviderName, string> = {
  local: 'Usuario y contraseña',
  github: 'GitHub',
  google: 'Google',
  discord: 'Discord',
  oidc: 'OIDC',
}

export default function ProfilePage() {
  const t = useI18n()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const { setUser } = useAuthStore()

  const [unlinkTarget, setUnlinkTarget] = useState<ProviderName | null>(null)
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [changingPassword, setChangingPassword] = useState(false)

  const { data: setupStatus } = useQuery({
    queryKey: ['setup-status'],
    queryFn: api.auth.setupStatus,
  })

  const { data: providers = [] } = useQuery({
    queryKey: ['my-providers'],
    queryFn: api.me.providers,
    enabled: !!user,
  })

  const unlinkMutation = useMutation({
    mutationFn: (provider: ProviderName) => api.me.unlinkProvider(provider),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['my-providers'] })
      setUnlinkTarget(null)
      toast({ title: t.profile.unlinked })
    },
    onError: (err: Error) => {
      setUnlinkTarget(null)
      toast({ title: err.message, variant: 'destructive' })
    },
  })

  async function handleLinkProvider(provider: ProviderName) {
    try {
      const { url } = await api.auth.linkStart(provider)
      window.location.href = url
    } catch (err) {
      toast({ title: (err as Error).message, variant: 'destructive' })
    }
  }

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault()
    setChangingPassword(true)
    try {
      await api.auth.changePassword(oldPassword, newPassword)
      toast({ title: t.profile.passwordChanged })
      setOldPassword('')
      setNewPassword('')
      queryClient.invalidateQueries({ queryKey: ['my-providers'] })
    } catch (err) {
      toast({ title: (err as Error).message, variant: 'destructive' })
    } finally {
      setChangingPassword(false)
    }
  }

  const initials = user?.name
    ?.split(' ')
    .map((w) => w[0])
    .slice(0, 2)
    .join('')
    .toUpperCase()

  const linkedProviderNames = new Set(providers.map((p) => p.provider))
  const enabledProviders: ProviderName[] = (setupStatus?.enabled_providers ?? []).filter(
    (p) => p !== 'local',
  )
  const hasLocalProvider = linkedProviderNames.has('local')

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center px-6 h-14 border-b shrink-0">
        <h1 className="text-base font-semibold">{t.profile.title}</h1>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-6 max-w-2xl space-y-8">
          {/* User info */}
          <div className="flex items-center gap-4">
            <Avatar className="h-14 w-14">
              <AvatarFallback className="text-lg">{initials}</AvatarFallback>
            </Avatar>
            <div>
              <p className="font-semibold text-base">{user?.name}</p>
              <p className="text-sm text-muted-foreground">{user?.email}</p>
              <Badge variant={user?.role === 'admin' ? 'default' : 'secondary'} className="mt-1 text-xs capitalize">
                {user?.role}
              </Badge>
            </div>
          </div>

          <Separator />

          {/* Linked providers */}
          <section>
            <h2 className="text-sm font-semibold mb-1">{t.profile.linkedProviders}</h2>
            <p className="text-xs text-muted-foreground mb-3">
              Puedes vincular múltiples métodos de inicio de sesión a tu cuenta.
            </p>

            <div className="space-y-2">
              {providers.length === 0 && (
                <p className="text-sm text-muted-foreground">{t.profile.noProviders}</p>
              )}
              {providers.map((pi) => (
                <div key={pi.id} className="flex items-center justify-between rounded-lg border p-3 bg-card">
                  <div className="flex items-center gap-3">
                    <span className="text-muted-foreground">{providerIcons[pi.provider]}</span>
                    <div>
                      <p className="text-sm font-medium">{setupStatus?.provider_labels?.[pi.provider] || providerLabels[pi.provider]}</p>
                      {pi.email && <p className="text-xs text-muted-foreground">{pi.email}</p>}
                      {pi.username && <p className="text-xs text-muted-foreground">@{pi.username}</p>}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setUnlinkTarget(pi.provider)}
                    className="text-muted-foreground hover:text-destructive"
                  >
                    <Link2Off className="h-4 w-4 mr-1" />
                    {t.profile.unlinkProvider}
                  </Button>
                </div>
              ))}
            </div>

            {/* Available providers to link */}
            {enabledProviders.filter((p) => !linkedProviderNames.has(p)).length > 0 && (
              <div className="mt-4">
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                  {t.profile.availableProviders}
                </p>
                <div className="flex flex-wrap gap-2">
                  {enabledProviders
                    .filter((p) => !linkedProviderNames.has(p))
                    .map((p) => (
                      <Button
                        key={p}
                        variant="outline"
                        size="sm"
                        onClick={() => handleLinkProvider(p)}
                      >
                        <span className="mr-1.5">{providerIcons[p]}</span>
                        <Link2 className="h-3 w-3 mr-1" />
                        {setupStatus?.provider_labels?.[p] || providerLabels[p]}
                      </Button>
                    ))}
                </div>
              </div>
            )}
          </section>

          {/* Change password (only if local provider is linked) */}
          {hasLocalProvider && (
            <>
              <Separator />
              <section>
                <h2 className="text-sm font-semibold mb-3">
                  <KeyRound className="inline h-4 w-4 mr-1.5" />
                  {t.profile.changePassword}
                </h2>
                <form onSubmit={handleChangePassword} className="space-y-3 max-w-sm">
                  <div className="space-y-1">
                    <Label htmlFor="old-password">{t.profile.oldPassword}</Label>
                    <Input
                      id="old-password"
                      type="password"
                      value={oldPassword}
                      onChange={(e) => setOldPassword(e.target.value)}
                      autoComplete="current-password"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor="new-password">{t.profile.newPassword}</Label>
                    <Input
                      id="new-password"
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      autoComplete="new-password"
                    />
                  </div>
                  <Button type="submit" disabled={changingPassword || !oldPassword || !newPassword}>
                    {changingPassword ? 'Guardando...' : t.profile.savePassword}
                  </Button>
                </form>
              </section>
            </>
          )}
        </div>
      </ScrollArea>

      {/* Unlink confirmation dialog */}
      <Dialog open={!!unlinkTarget} onOpenChange={(open) => !open && setUnlinkTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t.profile.unlinkProvider}</DialogTitle>
            <DialogDescription>{t.profile.unlinkConfirm}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUnlinkTarget(null)}>
              {t.profile.cancel}
            </Button>
            <Button
              variant="destructive"
              onClick={() => unlinkTarget && unlinkMutation.mutate(unlinkTarget)}
              disabled={unlinkMutation.isPending}
            >
              {t.profile.confirm}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

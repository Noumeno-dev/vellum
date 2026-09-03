import { useState } from 'react'
import { useNavigate, useSearchParams, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Github, Chrome, MessageSquare, ShieldCheck } from 'lucide-react'
import { api } from '@/lib/api'
import type { ProviderName } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import { VellumLogo } from '@/components/VellumLogo'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { useToast } from '@/hooks/use-toast'
import { useI18n } from '@/lib/i18n'

const providerIcons: Partial<Record<ProviderName, React.ReactNode>> = {
  github: <Github className="h-4 w-4 mr-2" />,
  google: <Chrome className="h-4 w-4 mr-2" />,
  discord: <MessageSquare className="h-4 w-4 mr-2" />,
  oidc: <ShieldCheck className="h-4 w-4 mr-2" />,
}

const providerLabels: Partial<Record<ProviderName, string>> = {
  github: 'Continuar con GitHub',
  google: 'Continuar con Google',
  discord: 'Continuar con Discord',
  oidc: 'Continuar con OIDC',
}

export default function LoginPage() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const { setUser } = useAuthStore()
  const { toast } = useToast()
  const t = useI18n()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loggingIn, setLoggingIn] = useState(false)
  const [redirecting, setRedirecting] = useState<ProviderName | null>(null)

  const { data: status } = useQuery({
    queryKey: ['setup-status'],
    queryFn: api.auth.setupStatus,
  })

  const enabledProviders: ProviderName[] = status?.enabled_providers ?? []
  const hasLocal = enabledProviders.includes('local')
  const oauthProviders = enabledProviders.filter((p) => p !== 'local')

  // If no users exist yet, redirect to first-run setup.
  if (status && !status.has_users) {
    return <Navigate to="/setup" replace />
  }

  // Show error from OAuth redirect.
  const oauthError = params.get('error')

  async function handleLocalLogin(e: React.FormEvent) {
    e.preventDefault()
    if (!email || !password) {
      toast({ title: t.login.fillAll, variant: 'destructive' })
      return
    }
    setLoggingIn(true)
    try {
      const u = await api.auth.login(email, password)
      setUser(u)
      navigate('/')
    } catch (err) {
      toast({ title: (err as Error).message, variant: 'destructive' })
    } finally {
      setLoggingIn(false)
    }
  }

  async function handleOAuthLogin(provider: ProviderName) {
    setRedirecting(provider)
    try {
      const { url } = await api.auth.providerRedirect(provider)
      window.location.href = url
    } catch (err) {
      toast({ title: (err as Error).message, variant: 'destructive' })
      setRedirecting(null)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-sm">
        <div className="flex justify-center mb-8">
          <VellumLogo size={40} />
        </div>

        <Card>
          <CardHeader>
            <CardTitle>{t.login.title}</CardTitle>
            <CardDescription>{t.login.description}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {oauthError === 'policy' && (
              <p className="text-sm text-destructive text-center">
                Tu cuenta no tiene acceso a este sistema. Contacta al administrador.
              </p>
            )}
            {oauthError === 'oauth' && (
              <p className="text-sm text-destructive text-center">
                Error en el inicio de sesión externo. Intenta de nuevo.
              </p>
            )}

            {/* Local form */}
            {hasLocal && (
              <form onSubmit={handleLocalLogin} className="space-y-3">
                <div className="space-y-1.5">
                  <Label htmlFor="email">{t.login.email}</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="tu@email.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    required
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="password">{t.login.password}</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                  />
                </div>
                <Button type="submit" className="w-full" disabled={loggingIn}>
                  {loggingIn ? t.login.submitting : t.login.submit}
                </Button>
              </form>
            )}

            {/* OAuth providers */}
            {hasLocal && oauthProviders.length > 0 && <Separator />}
            {oauthProviders.map((provider) => (
              <Button
                key={provider}
                variant="outline"
                className="w-full"
                onClick={() => handleOAuthLogin(provider)}
                disabled={!!redirecting}
              >
                {providerIcons[provider]}
                {redirecting === provider ? 'Redirigiendo...' : (status?.provider_labels?.[provider] || providerLabels[provider] || `Continuar con ${provider}`)}
              </Button>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

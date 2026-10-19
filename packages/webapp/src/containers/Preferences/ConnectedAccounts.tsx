import React from 'react';
import { Button, Callout, FormGroup, InputGroup, Spinner } from '@blueprintjs/core';
import intl from 'react-intl-universal';
import useApiRequest from '@/hooks/useRequest';
import { socialError, socialProviderLabels } from '../Authentication/SocialLoginButtons';

export default function ConnectedAccounts() {
  const api = useApiRequest();
  const [providers, setProviders] = React.useState<string[]>([]);
  const [connections, setConnections] = React.useState<string[]>([]);
  const [hasPassword, setHasPassword] = React.useState(false);
  const [password, setPassword] = React.useState('');
  const [pending, setPending] = React.useState(true);
  const [error, setError] = React.useState('');
  const [success, setSuccess] = React.useState('');
  React.useEffect(() => {
    let active = true;
    const params = new URLSearchParams(window.location.hash.slice(1));
    if (params.get('error')) setError(socialError(params.get('error')));
    if (params.get('linked')) {
      setSuccess(intl.get('social.connected'));
    }
    window.history.replaceState(null, '', window.location.pathname);
    Promise.all([api.get('auth/social/providers'), api.get('auth/social/connections')]).then(([available, current]) => {
      if (!active) return;
      setProviders(available.data.providers);
      setConnections(current.data.connections.map((entry: { provider: string }) => entry.provider));
      setHasPassword(current.data.has_password);
      setPending(false);
    }).catch((err) => { if (active) { setError(socialError(err)); setPending(false); } });
    return () => { active = false; };
  }, [api]);
  const act = async (provider: string, connected: boolean) => {
    setPending(true); setError(''); setSuccess('');
    try {
      if (connected) {
        await api.http.delete(`/api/auth/social/connections/${provider}`, { data: { password } });
        setConnections((current) => current.filter((name) => name !== provider));
        setSuccess(intl.get('social.disconnected'));
        setPassword(''); setPending(false);
      } else {
        const res = await api.post(`auth/social/connections/${provider}`, { password });
        setPassword(''); window.location.assign(res.data.url);
      }
    } catch (err) { setError(socialError(err)); setPassword(''); setPending(false); }
  };
  const visible = Array.from(new Set([...providers, ...connections]));
  return <section style={{ padding: 24 }} aria-labelledby="connected-accounts-title">
    <h1 id="connected-accounts-title">{intl.get('social.connected_accounts')}</h1>
    <p>{intl.get('social.personal_settings')}</p>
    {hasPassword ? <FormGroup label={intl.get('social.confirm_password')} labelFor="connection-password">
      <InputGroup id="connection-password" type="password" autoComplete="current-password" value={password}
        onChange={(e) => setPassword(e.target.value)} />
    </FormGroup> : <p>{intl.get('social.fresh_login')}</p>}
    {error && <Callout intent="danger" role="alert">{error}</Callout>}
    {success && <Callout intent="success" role="status">{success}</Callout>}
    {pending && <Spinner aria-label={intl.get('social.loading')} />}
    {!pending && !visible.length && <p>{intl.get('social.unavailable')}</p>}
    {visible.map((provider) => {
      const connected = connections.includes(provider);
      return <div key={provider} style={{ marginTop: 16 }}>
        <span>{(socialProviderLabels[provider] || provider)} — {intl.get(connected ? 'social.is_connected' : 'social.not_connected')} </span>
        <Button disabled={pending || (hasPassword && !password) || (!connected && !providers.includes(provider))}
          onClick={() => act(provider, connected)}>
          {intl.get(connected ? 'social.disconnect' : 'social.connect', { provider: (socialProviderLabels[provider] || provider) })}
        </Button>
      </div>;
    })}
  </section>;
}

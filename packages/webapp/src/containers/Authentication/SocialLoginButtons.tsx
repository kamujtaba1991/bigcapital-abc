import React from 'react';
import { Button, Callout } from '@blueprintjs/core';
import intl from 'react-intl-universal';
import useApiRequest from '@/hooks/useRequest';

export const socialProviderLabels: Record<string, string> = { google: 'Google', facebook: 'Facebook', x: 'Twitter/X' };

export function socialError(error: any) {
  const code = typeof error === 'string' ? error : error?.response?.data?.errors?.[0]?.type || error?.message;
  const keys: Record<string, string> = {
    SIGN_IN_TO_CONNECT: 'social.collision', ALREADY_CONNECTED: 'social.already_connected',
    REAUTHENTICATE: 'social.reauthenticate', LAST_LOGIN_METHOD: 'social.last_method',
    SIGNUP_RESTRICTED: 'social.signup_restricted', EXPIRED: 'social.expired', CANCELED: 'social.canceled',
    UNAVAILABLE: 'social.unavailable', TRY_LATER: 'social.try_later',
  };
  return intl.get(keys[code] || 'social.failed');
}

export default function SocialLoginButtons({ intent }: { intent: 'login' | 'signup' }) {
  const api = useApiRequest();
  const [providers, setProviders] = React.useState<string[]>([]);
  const [pending, setPending] = React.useState(false);
  const [error, setError] = React.useState('');
  React.useEffect(() => {
    let active = true;
    api.get('auth/social/providers').then((res) => { if (active) setProviders(res.data.providers); }).catch(() => {});
    return () => { active = false; };
  }, [api]);
  const start = async (provider: string) => {
    setPending(true);
    setError('');
    try {
      const res = await api.post(`auth/social/${provider}/start`, { intent });
      window.location.assign(res.data.url);
    } catch (err) { setError(socialError(err)); setPending(false); }
  };
  return <div aria-label={intl.get('social.options')}>
    {providers.map((provider) => <Button key={provider} type="button" fill disabled={pending}
      onClick={() => start(provider)} style={{ marginTop: 8 }}>
      {intl.get('social.continue_with', { provider: socialProviderLabels[provider] || provider })}
    </Button>)}
    {error && <Callout intent="danger" role="alert">{error}</Callout>}
  </div>;
}

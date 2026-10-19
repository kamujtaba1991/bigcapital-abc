import crypto from 'crypto';
import google from './providers/Google';
import facebook from './providers/Facebook';
import { SocialAuthError, SocialProfile, SocialProvider } from './SocialProvider';
export { SocialAuthError } from './SocialProvider';
export type { SocialProfile } from './SocialProvider';

export const socialProviders: Record<string, SocialProvider> = { google, facebook };
export const providerNames = () => Object.keys(socialProviders);
export const randomToken = () => crypto.randomBytes(32).toString('hex');
export const tokenHash = (value: string) => crypto.createHash('sha256').update(value).digest('hex');

export function frontendURL() {
  const url = new URL(process.env.BASE_URL || '');
  if (url.username || url.password || url.search || url.hash ||
    (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) {
    throw new SocialAuthError('UNAVAILABLE');
  }
  return url;
}

export function providerConfig(provider: string) {
  if (!providerNames().includes(provider)) throw new SocialAuthError('UNAVAILABLE');
  const clientId = process.env[socialProviders[provider].clientIdEnv];
  const secret = process.env[socialProviders[provider].secretEnv];
  const redirectUri = process.env[`${provider.toUpperCase()}_REDIRECT_URI`];
  if (!clientId || !secret || !redirectUri) throw new SocialAuthError('UNAVAILABLE');
  const frontend = frontendURL();
  const callback = new URL(redirectUri);
  if (callback.origin !== frontend.origin || callback.pathname !== `/api/auth/social/${provider}/callback` || callback.search || callback.hash ||
    callback.username || callback.password || (callback.protocol !== 'https:' &&
    !(callback.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(callback.hostname)))) {
    throw new SocialAuthError('UNAVAILABLE');
  }
  return { clientId, secret, redirectUri };
}

export function authorizationURL(provider: string, state: string, verifier: string, nonce: string) {
  const { clientId, redirectUri } = providerConfig(provider);
  const selected = socialProviders[provider];
  const url = new URL(selected.authorizationEndpoint);
  url.search = new URLSearchParams({
    client_id: clientId, redirect_uri: redirectUri, response_type: 'code', state,
    scope: selected.scope,
  }).toString();
  if (selected.pkce) {
    url.searchParams.set('code_challenge', crypto.createHash('sha256').update(verifier).digest('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'));
    url.searchParams.set('code_challenge_method', 'S256');
  }
  if (selected.nonce) url.searchParams.set('nonce', nonce);
  return url.toString();
}


export async function exchangeProfile(provider: string, code: string, verifier: string, nonce: string): Promise<SocialProfile> {
  const config = providerConfig(provider);
  const profile = await socialProviders[provider].exchange(config, code, verifier, nonce);
  if (!profile || typeof profile.subject !== 'string' || !profile.subject || profile.subject.length > 191) {
    throw new SocialAuthError('INVALID_PROVIDER');
  }
  return { provider, subject: profile.subject, email: typeof profile.email === 'string' ? profile.email.trim().toLowerCase() : '',
    emailVerified: profile.emailVerified, firstName: profile.firstName || '', lastName: profile.lastName || '' };
}

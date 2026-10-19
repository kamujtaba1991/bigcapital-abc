import axios from 'axios';
import crypto from 'crypto';
import JWT from 'jsonwebtoken';

export const providerNames = ['google', 'facebook', 'x'];
export const randomToken = () => crypto.randomBytes(32).toString('hex');
export const tokenHash = (value: string) => crypto.createHash('sha256').update(value).digest('hex');
const http = axios.create({ timeout: 10000, maxRedirects: 0 });

export class SocialAuthError extends Error {
  constructor(public code: string) { super(code); }
}

export function frontendURL() {
  const url = new URL(process.env.BASE_URL || '');
  if (url.username || url.password || url.search || url.hash ||
    (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) {
    throw new SocialAuthError('UNAVAILABLE');
  }
  return url;
}

export function providerConfig(provider: string) {
  if (!providerNames.includes(provider)) throw new SocialAuthError('UNAVAILABLE');
  const prefix = provider === 'facebook' ? 'FACEBOOK_APP' : `${provider.toUpperCase()}_CLIENT`;
  const clientId = process.env[`${prefix}_ID`];
  const secret = process.env[`${prefix}_SECRET`];
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
  const endpoints = {
    google: 'https://accounts.google.com/o/oauth2/v2/auth',
    facebook: 'https://www.facebook.com/v26.0/dialog/oauth',
    x: 'https://x.com/i/oauth2/authorize',
  };
  const url = new URL(endpoints[provider]);
  url.search = new URLSearchParams({
    client_id: clientId, redirect_uri: redirectUri, response_type: 'code', state,
    scope: provider === 'google' ? 'openid email profile' :
      provider === 'facebook' ? 'public_profile,email' : 'tweet.read users.read users.email',
  }).toString();
  if (provider !== 'facebook') {
    url.searchParams.set('code_challenge', crypto.createHash('sha256').update(verifier).digest('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'));
    url.searchParams.set('code_challenge_method', 'S256');
  }
  if (provider === 'google') url.searchParams.set('nonce', nonce);
  return url.toString();
}

export interface SocialProfile {
  provider: string;
  subject: string;
  email: string;
  emailVerified: boolean;
  firstName: string;
  lastName: string;
}

export async function exchangeProfile(provider: string, code: string, verifier: string, nonce: string): Promise<SocialProfile> {
  const { clientId, secret, redirectUri } = providerConfig(provider);
  let profile: any;
  if (provider === 'google') {
    const { data } = await http.post('https://oauth2.googleapis.com/token', new URLSearchParams({
      grant_type: 'authorization_code', code, client_id: clientId,
      client_secret: secret, redirect_uri: redirectUri, code_verifier: verifier,
    }).toString());
    const decoded: any = JWT.decode(data.id_token, { complete: true });
    if (!decoded?.header?.kid || decoded.header.alg !== 'RS256') throw new SocialAuthError('INVALID_PROVIDER');
    const certs = await http.get('https://www.googleapis.com/oauth2/v1/certs');
    const cert = certs.data[decoded.header.kid];
    if (typeof cert !== 'string') throw new SocialAuthError('INVALID_PROVIDER');
    profile = JWT.verify(data.id_token, cert, { algorithms: ['RS256'], audience: clientId,
      issuer: ['https://accounts.google.com', 'accounts.google.com'] });
    if (profile.nonce !== nonce || typeof profile.exp !== 'number') throw new SocialAuthError('INVALID_PROVIDER');
    profile = { subject: profile.sub, email: profile.email, emailVerified: profile.email_verified === true,
      firstName: profile.given_name, lastName: profile.family_name };
  } else if (provider === 'facebook') {
    const { data } = await http.get('https://graph.facebook.com/v26.0/oauth/access_token', {
      params: { client_id: clientId, client_secret: secret, redirect_uri: redirectUri, code },
    });
    const debug = await http.get('https://graph.facebook.com/v26.0/debug_token', {
      params: { input_token: data.access_token, access_token: `${clientId}|${secret}` },
    });
    if (!debug.data.data?.is_valid || String(debug.data.data.app_id) !== clientId ||
      !Number.isFinite(debug.data.data.expires_at) || debug.data.data.expires_at * 1000 <= Date.now()) throw new SocialAuthError('INVALID_PROVIDER');
    const me = await http.get('https://graph.facebook.com/v26.0/me', {
      params: { fields: 'id,email,first_name,last_name' }, headers: { Authorization: `Bearer ${data.access_token}` },
    });
    if (String(me.data.id) !== String(debug.data.data.user_id)) throw new SocialAuthError('INVALID_PROVIDER');
    profile = { subject: me.data.id, email: me.data.email, emailVerified: false,
      firstName: me.data.first_name, lastName: me.data.last_name };
  } else {
    const { data } = await http.post('https://api.x.com/2/oauth2/token', new URLSearchParams({
      grant_type: 'authorization_code', code, client_id: clientId,
      redirect_uri: redirectUri, code_verifier: verifier,
    }).toString(), { auth: { username: clientId, password: secret } });
    const me = await http.get('https://api.x.com/2/users/me', {
      params: { 'user.fields': 'confirmed_email' }, headers: { Authorization: `Bearer ${data.access_token}` },
    });
    profile = { subject: me.data.data?.id, email: me.data.data?.confirmed_email,
      emailVerified: !!me.data.data?.confirmed_email, firstName: me.data.data?.name, lastName: '' };
  }
  if (typeof profile.subject !== 'string' || !profile.subject || profile.subject.length > 191) {
    throw new SocialAuthError('INVALID_PROVIDER');
  }
  return { provider, subject: profile.subject, email: typeof profile.email === 'string' ? profile.email.trim().toLowerCase() : '',
    emailVerified: profile.emailVerified, firstName: profile.firstName || '', lastName: profile.lastName || '' };
}

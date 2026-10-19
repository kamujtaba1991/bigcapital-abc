import JWT from 'jsonwebtoken';
import { providerHttp as http, SocialAuthError, SocialProvider } from '../SocialProvider';

const provider: SocialProvider = {
  clientIdEnv: 'GOOGLE_CLIENT_ID', secretEnv: 'GOOGLE_CLIENT_SECRET',
  authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth', scope: 'openid email profile',
  pkce: true, nonce: true,
  async exchange({ clientId, secret, redirectUri }, code, verifier, nonce) {
    let profile: any;
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
    const emailDomain = typeof profile.email === 'string' ? profile.email.split('@').pop()?.toLowerCase() : '';
    const authoritative = emailDomain === 'gmail.com' || (typeof profile.hd === 'string' && profile.hd.toLowerCase() === emailDomain);
    profile = { subject: profile.sub, email: profile.email, emailVerified: profile.email_verified === true && authoritative,
      firstName: profile.given_name, lastName: profile.family_name };
    return profile;
  },
};

export default provider;

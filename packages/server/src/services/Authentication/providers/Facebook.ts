import { providerHttp as http, SocialAuthError, SocialProvider } from '../SocialProvider';

const provider: SocialProvider = {
  clientIdEnv: 'FACEBOOK_APP_ID', secretEnv: 'FACEBOOK_APP_SECRET',
  authorizationEndpoint: 'https://www.facebook.com/v26.0/dialog/oauth', scope: 'public_profile,email',
  pkce: false, nonce: false,
  async exchange({ clientId, secret, redirectUri }, code, verifier, nonce) {
    let profile: any;
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
    return profile;
  },
};

export default provider;

import { providerHttp as http, SocialProvider } from '../SocialProvider';

const provider: SocialProvider = {
  clientIdEnv: 'X_CLIENT_ID', secretEnv: 'X_CLIENT_SECRET',
  authorizationEndpoint: 'https://x.com/i/oauth2/authorize', scope: 'tweet.read users.read users.email',
  pkce: true, nonce: false,
  async exchange({ clientId, secret, redirectUri }, code, verifier, nonce) {
    let profile: any;
    const { data } = await http.post('https://api.x.com/2/oauth2/token', new URLSearchParams({
      grant_type: 'authorization_code', code, client_id: clientId,
      redirect_uri: redirectUri, code_verifier: verifier,
    }).toString(), { auth: { username: clientId, password: secret } });
    const me = await http.get('https://api.x.com/2/users/me', {
      params: { 'user.fields': 'confirmed_email' }, headers: { Authorization: `Bearer ${data.access_token}` },
    });
    profile = { subject: me.data.data?.id, email: me.data.data?.confirmed_email,
      emailVerified: !!me.data.data?.confirmed_email, firstName: me.data.data?.name, lastName: '' };
    return profile;
  },
};

export default provider;

import { socialProviders } from '../../src/services/Authentication/SocialProviders';
import { providerHttp } from '../../src/services/Authentication/SocialProvider';

socialProviders.test = {
  clientIdEnv: 'TEST_CLIENT_ID', secretEnv: 'TEST_CLIENT_SECRET',
  authorizationEndpoint: 'https://identity.example/authorize', scope: 'profile email', pkce: true, nonce: false,
  async exchange() {
    const { data } = await providerHttp.get('https://identity.example/me');
    return { subject: data.data.id, email: data.data.confirmed_email, emailVerified: !!data.data.confirmed_email,
      firstName: data.data.name, lastName: '' };
  },
};

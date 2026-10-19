import path from 'path';
import { register } from 'tsconfig-paths';
import 'reflect-metadata';

const root = path.resolve(__dirname, '../..');
register({ baseUrl: path.join(root, 'src'), paths: { '@/*': ['*'] } });
global.__root_dir = root;
global.__views_dir = path.join(root, 'src/resources/views');
process.env.BASE_URL = 'https://finance.example';
process.env.JWT_SECRET = 'test-only-app-secret';
for (const provider of ['GOOGLE', 'FACEBOOK', 'X']) {
  const prefix = provider === 'FACEBOOK' ? 'FACEBOOK_APP' : `${provider}_CLIENT`;
  process.env[`${prefix}_ID`] = `${provider.toLowerCase()}-client`;
  process.env[`${prefix}_SECRET`] = 'test-only-provider-secret';
  process.env[`${provider}_REDIRECT_URI`] = `https://finance.example/api/auth/social/${provider.toLowerCase()}/callback`;
}

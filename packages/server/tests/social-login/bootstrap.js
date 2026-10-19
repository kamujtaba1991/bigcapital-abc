import path from 'path';
import { register } from 'tsconfig-paths';
import 'reflect-metadata';

const root = path.resolve(__dirname, '../..');
register({ baseUrl: path.join(root, 'src'), paths: { '@/*': ['*'] } });
global.__root_dir = root;
global.__views_dir = path.join(root, 'src/resources/views');
process.env.BASE_URL = 'https://finance.example';
process.env.JWT_SECRET = 'test-only-app-secret';
process.env.TEST_CLIENT_ID = 'test-client';
process.env.TEST_CLIENT_SECRET = 'test-only-provider-secret';
process.env.TEST_REDIRECT_URI = 'https://finance.example/api/auth/social/test/callback';

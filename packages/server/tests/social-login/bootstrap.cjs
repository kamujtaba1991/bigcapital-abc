const path = require('node:path');
const Module = require('node:module');
const root = path.resolve(__dirname, '../..');
process.env.TS_NODE_PROJECT = path.join(root, 'tsconfig.json');
process.env.TS_NODE_COMPILER_OPTIONS = JSON.stringify({ jsx: 'react' });
process.env.NODE_PATH = path.join(root, 'src');
Module._initPaths();
const resolve = Module._resolveFilename;
Module._resolveFilename = function (name, parent, ...args) {
  return resolve.call(this, name.startsWith('@/') ? path.join(root, 'src', name.slice(2)) : name, parent, ...args);
};
global.__root_dir = root;
global.__views_dir = path.join(root, 'src/resources/views');
require('ts-node/register/transpile-only');
require('reflect-metadata');
process.env.BASE_URL = 'https://finance.example';
process.env.JWT_SECRET = 'test-only-app-secret';
for (const provider of ['GOOGLE', 'FACEBOOK', 'X']) {
  const prefix = provider === 'FACEBOOK' ? 'FACEBOOK_APP' : `${provider}_CLIENT`;
  process.env[`${prefix}_ID`] = `${provider.toLowerCase()}-client`;
  process.env[`${prefix}_SECRET`] = 'test-only-provider-secret';
  process.env[`${provider}_REDIRECT_URI`] = `https://finance.example/api/auth/social/${provider.toLowerCase()}/callback`;
}

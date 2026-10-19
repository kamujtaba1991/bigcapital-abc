import './bootstrap';
import './providerMock';
import './testProvider';
import assert from 'node:assert/strict';
import * as providers from '../../src/services/Authentication/SocialProviders';

describe('Shared social authentication', () => {
  it('authorization URLs bind state and callback and respect the configured PKCE scopes', () => {
    for (const name of providers.providerNames()) {
      const url = new URL(providers.authorizationURL(name, 'state', 'verifier', 'nonce'));
      assert.equal(url.searchParams.get('state'), 'state');
      assert.equal(url.searchParams.get('redirect_uri'), process.env[`${name.toUpperCase()}_REDIRECT_URI`]);
      assert.ok(!/offline|write/.test(url.searchParams.get('scope')));
      if (providers.socialProviders[name].pkce) assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    }
  });
  it('callback configuration rejects external origins, credentials, unsafe protocols and paths', () => {
    const original = process.env.TEST_REDIRECT_URI;
    for (const value of ['https://evil.example/api/auth/social/test/callback', 'http://finance.example/api/auth/social/test/callback',
      'https://a:b@finance.example/api/auth/social/test/callback', 'https://finance.example/wrong']) {
      process.env.TEST_REDIRECT_URI = value;
      assert.throws(() => providers.providerConfig('test'));
    }
    process.env.TEST_REDIRECT_URI = original;
    assert.throws(() => providers.providerConfig('__proto__'));
  });
  it('opaque tokens have full entropy and storage hashes do not reveal the token', () => {
    const a = providers.randomToken();
    assert.match(a, /^[a-f0-9]{64}$/);
    assert.notEqual(a, providers.randomToken());
    assert.notEqual(providers.tokenHash(a), a);
  });

});

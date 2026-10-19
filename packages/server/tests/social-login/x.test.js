import './bootstrap';
import './providerMock';
import assert from 'node:assert/strict';
import { providerMock } from './providerMock';
import * as providers from '../../src/services/Authentication/SocialProviders';

process.env.X_CLIENT_ID = 'x-client';
process.env.X_CLIENT_SECRET = 'test-only-provider-secret';
process.env.X_REDIRECT_URI = 'https://finance.example/api/auth/social/x/callback';

describe('Twitter/X sign-in', () => {
  let responses;
  let calls;
  beforeEach(() => {
    calls = [];
    providerMock.respond = (config) => {
      calls.push(config);
      const data = responses[config.url];
      assert.ok(data, `Unexpected HTTP call: ${config.url}`);
      return data;
    };
  });
  it('requests only the required Twitter/X authorization permissions', () => {
    const url = new URL(providers.authorizationURL('x', 'state', 'verifier', 'nonce'));
    assert.equal(url.origin + url.pathname, 'https://x.com/i/oauth2/authorize');
    assert.equal(url.searchParams.get('scope'), 'tweet.read users.read users.email');
    assert.equal(url.searchParams.get('code_challenge_method'), "S256");
    assert.equal(url.searchParams.get('nonce'), null);
  });
  it('X uses confidential OAuth2 credentials, PKCE and stable user ID, with missing-email fallback', async () => {
    calls = [];
    responses = { 'https://api.x.com/2/oauth2/token': { access_token: 'x-token' },
      'https://api.x.com/2/users/me': { data: { id: '9999999999999999999', name: 'Person' } } };
    const profile = await providers.exchangeProfile('x', 'code', 'verifier', '');
    assert.equal(profile.subject, '9999999999999999999');
    assert.equal(profile.emailVerified, false);
    assert.equal(calls[0].auth.username, 'x-client');
    assert.ok(calls[0].data.includes('code_verifier=verifier'));
    assert.equal(calls[1].headers.Authorization, 'Bearer x-token');
  });

});

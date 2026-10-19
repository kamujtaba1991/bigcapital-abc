import './bootstrap';
import './providerMock';
import assert from 'node:assert/strict';
import { providerMock } from './providerMock';
import * as providers from '../../src/services/Authentication/SocialProviders';
import crypto from 'node:crypto';
import JWT from 'jsonwebtoken';
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

process.env.GOOGLE_CLIENT_ID = 'google-client';
process.env.GOOGLE_CLIENT_SECRET = 'test-only-provider-secret';
process.env.GOOGLE_REDIRECT_URI = 'https://finance.example/api/auth/social/google/callback';

describe('Google sign-in', () => {
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
  function googleToken(overrides = {}, options = {}) {
    return JWT.sign({ sub: 'google-subject', nonce: 'nonce', email: 'Person@Example.com', email_verified: true,
      given_name: 'Person', ...overrides }, privateKey,
    { algorithm: 'RS256', keyid: 'test-key', audience: 'google-client', issuer: 'https://accounts.google.com', expiresIn: 60, ...options });
  }
  function googleResponses(token) {
    calls = [];
    responses = { 'https://oauth2.googleapis.com/token': { id_token: token },
      'https://www.googleapis.com/oauth2/v1/certs': { 'test-key': publicKey.export({ type: 'spki', format: 'pem' }) } };
  }
  it('requests only the required Google authorization permissions', () => {
    const url = new URL(providers.authorizationURL('google', 'state', 'verifier', 'nonce'));
    assert.equal(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
    assert.equal(url.searchParams.get('scope'), 'openid email profile');
    assert.equal(url.searchParams.get('code_challenge_method'), "S256");
    assert.equal(url.searchParams.get('nonce'), "nonce");
  });
  it('Google validates signed identity and normalizes email, not subject', async () => {
    googleResponses(googleToken());
    const profile = await providers.exchangeProfile('google', 'code', 'verifier', 'nonce');
    assert.equal(profile.subject, 'google-subject');
    assert.equal(profile.email, 'person@example.com');
    assert.equal(profile.emailVerified, false);
    assert.ok(calls[0].data.includes('code_verifier=verifier'));
  });
  it('Google only attests mailbox ownership for Gmail or its matching hosted domain', async () => {
    for (const [claims, expected] of [[{ email: 'person@gmail.com' }, true],
      [{ hd: 'example.com' }, true], [{ hd: 'different.example' }, false]]) {
      googleResponses(googleToken(claims));
      assert.equal((await providers.exchangeProfile('google', 'code', 'verifier', 'nonce')).emailVerified, expected);
    }
  });
  it('Google rejects wrong nonce, audience, issuer, expiry and signature', async () => {
    for (const token of [googleToken({ nonce: 'attacker' }), googleToken({}, { audience: 'other-client' }),
      googleToken({}, { issuer: 'https://evil.example' }), googleToken({}, { expiresIn: -1 }),
      JWT.sign({ sub: 'fake' }, 'attacker-secret', { algorithm: 'HS256', keyid: 'test-key' })]) {
      googleResponses(token);
      await assert.rejects(providers.exchangeProfile('google', 'code', 'verifier', 'nonce'));
    }
  });

});

import './bootstrap';
import './providerMock';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import JWT from 'jsonwebtoken';
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
let responses;
let calls;
import { providerMock } from './providerMock';
import * as providers from '../../src/services/Authentication/SocialProviders';

describe('Social providers', () => {
  beforeEach(() => {
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
  it('all authorization URLs bind state and callback; Google/X use S256 and no offline access', () => {
    for (const name of providers.providerNames) {
      const url = new URL(providers.authorizationURL(name, 'state', 'verifier', 'nonce'));
      assert.equal(url.searchParams.get('state'), 'state');
      assert.equal(url.searchParams.get('redirect_uri'), process.env[`${name.toUpperCase()}_REDIRECT_URI`]);
      assert.ok(!/offline|write/.test(url.searchParams.get('scope')));
      if (name !== 'facebook') assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    }
  });
  it('callback configuration rejects external origins, credentials, unsafe protocols and paths', () => {
    const original = process.env.GOOGLE_REDIRECT_URI;
    for (const value of ['https://evil.example/api/auth/social/google/callback', 'http://finance.example/api/auth/social/google/callback',
      'https://a:b@finance.example/api/auth/social/google/callback', 'https://finance.example/wrong']) {
      process.env.GOOGLE_REDIRECT_URI = value;
      assert.throws(() => providers.providerConfig('google'));
    }
    process.env.GOOGLE_REDIRECT_URI = original;
    assert.throws(() => providers.providerConfig('__proto__'));
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
  it('Facebook validates app and user identity; absent email stays absent/unverified', async () => {
    calls = [];
    responses = { 'https://graph.facebook.com/v26.0/oauth/access_token': { access_token: 'provider-token' },
      'https://graph.facebook.com/v26.0/debug_token': { data: { is_valid: true, app_id: 'facebook-client', user_id: 'FB-ID', expires_at: Date.now() / 1000 + 60 } },
      'https://graph.facebook.com/v26.0/me': { id: 'FB-ID', first_name: 'Person' } };
    const profile = await providers.exchangeProfile('facebook', 'code', '', '');
    assert.equal(profile.subject, 'FB-ID');
    assert.equal(profile.email, '');
    assert.equal(profile.emailVerified, false);
    responses['https://graph.facebook.com/v26.0/debug_token'].data.app_id = 'other-app';
    await assert.rejects(providers.exchangeProfile('facebook', 'code', '', ''));
    responses['https://graph.facebook.com/v26.0/debug_token'].data.app_id = 'facebook-client';
    responses['https://graph.facebook.com/v26.0/me'].id = 'other-user';
    await assert.rejects(providers.exchangeProfile('facebook', 'code', '', ''));
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
  it('opaque tokens have full entropy and storage hashes do not reveal the token', () => {
    const a = providers.randomToken();
    assert.match(a, /^[a-f0-9]{64}$/);
    assert.notEqual(a, providers.randomToken());
    assert.notEqual(providers.tokenHash(a), a);
  });

});

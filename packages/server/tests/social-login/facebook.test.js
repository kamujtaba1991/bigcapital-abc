import './bootstrap';
import './providerMock';
import assert from 'node:assert/strict';
import { providerMock } from './providerMock';
import * as providers from '../../src/services/Authentication/SocialProviders';

process.env.FACEBOOK_APP_ID = 'facebook-client';
process.env.FACEBOOK_APP_SECRET = 'test-only-provider-secret';
process.env.FACEBOOK_REDIRECT_URI = 'https://finance.example/api/auth/social/facebook/callback';

describe('Facebook sign-in', () => {
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
  it('requests only the required Facebook authorization permissions', () => {
    const url = new URL(providers.authorizationURL('facebook', 'state', 'verifier', 'nonce'));
    assert.equal(url.origin + url.pathname, 'https://www.facebook.com/v26.0/dialog/oauth');
    assert.equal(url.searchParams.get('scope'), 'public_profile,email');
    assert.equal(url.searchParams.get('code_challenge_method'), null);
    assert.equal(url.searchParams.get('nonce'), null);
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

});

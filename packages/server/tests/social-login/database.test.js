import expressBoom from 'express-boom';
import './bootstrap';
import './providerMock';
import Knex from 'knex';
import { JSONResponseTransformer, snakecaseResponseTransformer } from '../../src/api/middleware/JSONResponseTransformer';
import AttachUser from '../../src/api/middleware/AttachCurrentTenantUser';
import JWTAuth from '../../src/api/middleware/jwtAuth';
import Controller from '../../src/api/controllers/SocialAuthentication';
import express from 'express';
import assert from 'node:assert/strict';
import { Container } from 'typedi';
import { Model, knexSnakeCaseMappers } from 'objection';
import { providerMock } from './providerMock';
import { SocialAuth } from '../../src/services/Authentication/SocialAuth';
import { SocialAttempts } from '../../src/services/Authentication/SocialAttempts';
import { AuthSignupService } from '../../src/services/Authentication/AuthSignup';
import { AuthSigninService } from '../../src/services/Authentication/AuthSignin';
import { AuthSendResetPassword } from '../../src/services/Authentication/AuthSendResetPassword';
import { SystemUser, Tenant } from '../../src/system/models';
import { EventPublisher } from '../../src/lib/EventPublisher/EventPublisher';
import { SubscribeFreeOnSignupCommunity } from '../../src/services/Subscription/events/SubscribeFreeOnSignupCommunity';
import { Subscription } from '../../src/services/Subscription/Subscription';
import config from '../../src/config';
import * as migration from '../../src/system/migrations/20261019000000_social_login';
import JWT from 'jsonwebtoken';

let profile;

describe('MySQL social login integration', function () {
  if (!process.env.SOCIAL_TEST_DATABASE_URL) {
    it('requires an empty *_social_test database (CI supplies it)', function () { this.skip(); });
    return;
  }
  const dbURL = new URL(process.env.SOCIAL_TEST_DATABASE_URL);
  assert.match(dbURL.pathname, /_social_test$/);
  const knex = Knex({ client: 'mysql2', connection: process.env.SOCIAL_TEST_DATABASE_URL,
    ...knexSnakeCaseMappers({ upperCase: true }), pool: { min: 0, max: 8 } });
  let created = false;
  const browser = 'b'.repeat(64);
  let sentMail;
  const bus = new EventPublisher();
  const attempts = new SocialAttempts(); attempts.knex = knex;
  const social = new SocialAuth(); social.knex = knex; social.attempts = attempts;
  const signup = new AuthSignupService();
  const signin = new AuthSigninService();
  const repository = {
    findOneById: (id) => SystemUser.query().findById(id),
    findOneByEmail: (email) => SystemUser.query().findOne('email', email),
    patchLastLoginAt: (id) => knex('users').where({ id }).update({ lastLoginAt: new Date() }),
    create: (data) => SystemUser.query().insert(data),
    update: (data, where) => knex('users').where(where).update(data),
  };
  signup.sysRepositories = signin.sysRepositories = { systemUserRepository: repository };
  signup.eventPublisher = signin.eventPublisher = bus;
  signup.tenantsManager = { createTenant: () => Tenant.query().insert({ organizationId: `password-${Date.now()}` }) };
  social.signup = signup; social.signin = signin;
  const subscriber = new SubscribeFreeOnSignupCommunity(); subscriber.subscriptionService = new Subscription();
  subscriber.attach({ subscribe: (name, fn) => bus.emitter.on(name, fn) });
  Container.set('logger', { info() {}, error() {} });
  Container.set('repositories', { systemUserRepository: repository });
  Container.set('mail', { sendMail: (mail, cb) => { sentMail = mail; cb(null); } });
  Container.set('rateLimiter.login', { get: async () => null, hit: async () => {}, reset: async () => {} });
  Model.knex(knex);
  const beginProfile = async (subject, email = 'new@example.com') => {
    profile = { id: subject, confirmed_email: email, name: 'New' };
    providerMock.respond = (request) => request.url.endsWith('/token') ? { access_token: 'mock-provider-token' } : { data: profile };
    const url = await social.start('x', 'signup', browser);
    return social.callback('x', new URL(url).searchParams.get('state'), 'code', browser, '');
  };
  const values = (email = 'new@example.com') => ({ email, firstName: 'New', lastName: 'Person' });
  before(async () => {
    assert.equal(await knex.schema.hasTable('users'), false, 'Refuse to modify an existing users table');
    created = true;
    await (await import('../../src/system/migrations/20200420134631_create_tenants_table')).up(knex);
    await (await import('../../src/system/migrations/20200420134633_create_users_table')).up(knex);
    await (await import('../../src/system/migrations/20190104195900_create_password_resets_table')).up(knex);
    await knex.schema.table('users', (table) => { table.boolean('verified'); table.string('verifyToken'); });
    await (await import('../../src/system/migrations/20200823235340_create_tenants_metadata_table')).up(knex);
    await knex.schema.createTable('subscriptionPlans', (table) => {
      table.increments(); table.string('slug'); table.integer('price'); table.string('invoiceInterval'); table.integer('invoicePeriod');
    });
    await (await import('../../src/system/migrations/20200823234636_create_subscription_plan_subscription')).up(knex);
    await knex('subscriptionPlans').insert({ slug: 'free', price: 0 });
    await migration.up(knex);
  });

  it('state is browser-bound, one-use, expiring and atomic under concurrent consumption', async () => {
    const token = await attempts.create('state', browser, { value: 1 });
    await assert.rejects(attempts.consume(token, 'state', 'c'.repeat(64)));
    const outcomes = await Promise.allSettled([attempts.consume(token, 'state', browser), attempts.consume(token, 'state', browser)]);
    assert.equal(outcomes.filter((r) => r.status === 'fulfilled').length, 1);
    const expired = await attempts.create('state', browser, {});
    await knex('socialAttempts').update({ expiresAt: new Date(Date.now() - 1000) });
    await assert.rejects(attempts.consume(expired, 'state', browser));
  });
  it('fresh social signup creates one user/company/identity/free subscription; handoff returns existing JWT contract', async () => {
    const pending = await beginProfile('x-new');
    assert.equal((await knex('users')).length, 0);
    const result = await social.complete(pending.ticket, browser, values());
    const auth = await social.exchange(result.ticket, browser);
    assert.equal(JWT.verify(auth.token, process.env.JWT_SECRET).id, auth.user.id);
    assert.equal(auth.tenant.id, auth.user.tenantId);
    assert.equal(auth.user.password, undefined);
    assert.equal(auth.user.verifyToken, undefined);
    assert.ok(auth.user.verified);
    assert.equal((await knex('tenants')).length, 1);
    assert.equal((await knex('socialIdentities')).length, 1);
    assert.equal((await knex('subscriptionPlanSubscriptions')).length, 1);
    assert.ok((await knex('users').first()).lastLoginAt);
    await assert.rejects(social.exchange(result.ticket, browser));
  });
  it('known provider ID ignores changed email; unknown identity matching email never merges', async () => {
    const known = await beginProfile('x-new', 'changed@example.com');
    assert.equal(known.registration, undefined);
    const auth = await social.exchange(known.ticket, browser);
    assert.equal(auth.user.email, 'new@example.com');
    await assert.rejects(beginProfile('x-other', 'NEW@example.com'), { code: 'SIGN_IN_TO_CONNECT' });
    assert.equal((await knex('tenants')).length, 1);
  });
  it('user-entered or missing email requires email proof before any company is created', async () => {
    const pending = await beginProfile('x-no-email', null);
    const result = await social.complete(pending.ticket, browser, values('verified@example.com'));
    assert.equal(result.verificationRequired, true);
    assert.equal((await knex('tenants')).length, 1);
    const code = sentMail.html.match(/<strong>([a-f0-9]{64})<\/strong>/)[1];
    await assert.rejects(social.verifyEmail(code, 'c'.repeat(64)));
    const completed = await social.verifyEmail(code, browser);
    assert.equal((await social.exchange(completed.ticket, browser)).user.email, 'verified@example.com');
    await assert.rejects(social.verifyEmail(code, browser));
  });
  it('password login remains valid; explicit link keeps original company; wrong session/identity ownership rejected', async () => {
    const passwordUser = await signup.signUp({ ...values('password@example.com'), password: 'test-password' });
    const passwordAuth = await signin.signIn('password@example.com', 'test-password');
    assert.equal(passwordAuth.user.id, passwordUser.id);
    await assert.rejects(social.freshUser(passwordUser.id, 'wrong', Date.now() / 1000));
    await social.freshUser(passwordUser.id, 'test-password', Date.now() / 1000);
    const link = async (subject, session = passwordAuth.token, callbackSession = session) => {
      profile = { id: subject, name: 'Linked' };
      const url = await social.start('x', 'link', browser, passwordUser.id, session);
      return social.callback('x', new URL(url).searchParams.get('state'), 'code', browser, callbackSession);
    };
    await assert.rejects(link('x-link', passwordAuth.token, 'different-session'), { code: 'REAUTHENTICATE' });
    await assert.rejects(link('x-new'), { code: 'ALREADY_CONNECTED' });
    await link('x-link');
    const existing = await beginProfile('x-link');
    assert.equal((await social.exchange(existing.ticket, browser)).user.tenantId, passwordUser.tenantId);
    await social.disconnect(passwordUser.id, 'x');
    assert.equal((await social.connections(passwordUser.id)).length, 0);
  });
  it('social-only account cannot remove its last usable login method; fresh authentication expires', async () => {
    const user = await SystemUser.query().findOne('email', 'new@example.com');
    await assert.rejects(social.disconnect(user.id, 'x'), { code: 'LAST_LOGIN_METHOD' });
    await assert.rejects(social.freshUser(user.id, '', Date.now() / 1000 - 600), { code: 'REAUTHENTICATE' });
  });
  it('social-only users can establish password recovery before disconnecting their provider', async () => {
    const user = await SystemUser.query().findOne('email', 'verified@example.com');
    const recovery = new AuthSendResetPassword();
    recovery.sysRepositories = { systemUserRepository: repository };
    recovery.eventPublisher = bus;
    const reset = await recovery.sendResetPassword(user.email);
    assert.match(reset.token, /^[a-f0-9]{64}$/);
    await recovery.resetPassword(reset.token, 'recovered-password');
    await assert.rejects(recovery.resetPassword(reset.token, 'replay-password'));
    await social.disconnect(user.id, 'x');
    assert.equal((await signin.signIn(user.email, 'recovered-password')).user.id, user.id);
  });
  it('inactive users and pending invitations cannot log in; invitations/deleted users still collide', async () => {
    const user = await SystemUser.query().findOne('email', 'new@example.com');
    await knex('users').where({ id: user.id }).update({ active: false });
    await assert.rejects(beginProfile('x-new'), { code: 'ACCOUNT_UNAVAILABLE' });
    await knex('users').where({ id: user.id }).update({ active: true, inviteAcceptedAt: null });
    await assert.rejects(beginProfile('x-new'), { code: 'ACCOUNT_UNAVAILABLE' });
    await assert.rejects(beginProfile('unlinked-invite', user.email), { code: 'SIGN_IN_TO_CONNECT' });
    await knex('users').where({ id: user.id }).update({ inviteAcceptedAt: new Date(), deletedAt: new Date() });
    await assert.rejects(beginProfile('unlinked-deleted', user.email), { code: 'SIGN_IN_TO_CONNECT' });
    await knex('users').where({ id: user.id }).update({ deletedAt: null });
  });
  it('signup restrictions apply before email dispatch and are rechecked after email proof', async () => {
    config.signupRestrictions = { disabled: true, allowedDomains: [], allowedEmails: [] };
    const pending = await beginProfile('restricted', 'restricted@example.com');
    await assert.rejects(social.complete(pending.ticket, browser, values('restricted@example.com')));
    config.signupRestrictions = { disabled: true, allowedDomains: ['allowed.example'], allowedEmails: [] };
    const allowed = await beginProfile('allowed', 'person@allowed.example');
    await social.complete(allowed.ticket, browser, values('person@allowed.example'));
    config.signupRestrictions = { disabled: false, allowedDomains: [], allowedEmails: [] };
  });
  it('HTTP callback -> SQL signup -> one-use handoff -> authenticated company data', async () => {
    const controller = new Controller(); controller.social = social;
    const app = express(); app.use(express.json()); app.use(expressBoom());
    app.use(JSONResponseTransformer(snakecaseResponseTransformer));
    app.use('/api/auth/social', controller.router());
    app.get('/company', JWTAuth, AttachUser, async (req, res) => {
      const tenant = await knex('tenants').where({ id: req.user.tenantId }).first();
      res.send({ userId: req.user.id, organizationId: tenant.organizationId });
    });
    const server = app.listen(0, '127.0.0.1');
    await new Promise((resolve) => server.once('listening', resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    let browserCookie = '';
    const post = (route, data) => fetch(`${origin}/api/auth/social/${route}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://finance.example', Cookie: browserCookie },
      body: JSON.stringify(data),
    });
    try {
      profile = { id: 'http-user', confirmed_email: 'http@example.com', name: 'HTTP' };
      const start = await post('x/start', { intent: 'signup' });
      browserCookie = start.headers.get('set-cookie').split(';')[0];
      const state = new URL((await start.json()).url).searchParams.get('state');
      const callback = await fetch(`${origin}/api/auth/social/x/callback?state=${state}&code=mock-code`, {
        headers: { Cookie: browserCookie }, redirect: 'manual',
      });
      assert.equal(callback.status, 303);
      const fragment = new URLSearchParams(new URL(callback.headers.get('location')).hash.slice(1));
      assert.equal(fragment.get('registration'), 'true');
      assert.ok(!callback.headers.get('location').includes('mock-provider-token'));
      const pending = await (await post('profile', { ticket: fragment.get('ticket') })).json();
      const created = await (await post('complete', { ticket: pending.ticket,
        email: pending.email, first_name: pending.first_name, last_name: 'Person' })).json();
      const session = await (await post('exchange', { ticket: created.ticket })).json();
      assert.ok(session.token);
      assert.equal(session.user.tenant_id, session.tenant.id);
      assert.equal((await post('exchange', { ticket: created.ticket })).status, 400);
      assert.equal((await fetch(`${origin}/company`)).status, 401);
      const company = await (await fetch(`${origin}/company`, { headers: { 'X-Access-Token': session.token } })).json();
      assert.equal(company.organization_id, session.tenant.organization_id);
      assert.equal(company.user_id, session.user.id);
    } finally { server.closeIdleConnections?.(); await new Promise((resolve) => server.close(resolve)); }
  });
  it('duplicate identity or subscriber failure rolls back company, user, identity and subscription', async () => {
    const before = (await knex('tenants')).length;
    const pending = await beginProfile('rollback', 'rollback@example.com');
    const fail = async () => { throw new Error('subscription failed'); };
    bus.emitter.on('onSignUp', fail);
    await assert.rejects(social.complete(pending.ticket, browser, values('rollback@example.com')));
    bus.emitter.off('onSignUp', fail);
    assert.equal((await knex('tenants')).length, before);
    assert.equal(await knex('users').where({ email: 'rollback@example.com' }).first(), undefined);
    const a = await beginProfile('concurrent', 'race@example.com');
    const b = await beginProfile('concurrent', 'race@example.com');
    const results = await Promise.allSettled([social.complete(a.ticket, browser, values('race@example.com')),
      social.complete(b.ticket, browser, values('race@example.com'))]);
    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal((await knex('tenants')).length, before + 1);
    await assert.rejects(knex('users').insert({ email: ' RACE@EXAMPLE.COM ' }));
  });
  after(async () => {
    if (created) {
      for (const name of ['socialAttempts', 'socialIdentities', 'passwordResets', 'subscriptionPlanSubscriptions', 'subscriptionPlans', 'tenantsMetadata', 'users', 'tenants']) {
        await knex.schema.dropTableIfExists(name);
      }
    }
    await knex.destroy();
  });
});

import { Container, Inject, Service } from 'typedi';
import { SystemUser } from '@/system/models';
import { AuthSigninService } from './AuthSignin';
import { AuthSignupService } from './AuthSignup';
import { SocialAttempts } from './SocialAttempts';
import { SocialAuthError, SocialProfile, randomToken, tokenHash, authorizationURL, exchangeProfile, providerConfig } from './SocialProviders';
import Mail from '@/lib/Mail';
import config from '@/config';

@Service()
export class SocialAuth {
  @Inject('knex') private knex: any;
  @Inject() private attempts: SocialAttempts;
  @Inject() private signin: AuthSigninService;
  @Inject() private signup: AuthSignupService;

  async freshUser(userId: number, password: string, issuedAt: number) {
    const user = await SystemUser.query().findById(userId);
    this.checkUser(user);
    if (user.password) {
      const limiter: any = Container.get('rateLimiter.login');
      const rate = await limiter.get(user.email);
      if (rate && rate.consumedPoints >= config.throttler.login.points) throw new SocialAuthError('TRY_LATER');
      if (!user.verifyPassword(password)) {
        await limiter.hit(user.email);
        throw new SocialAuthError('REAUTHENTICATE');
      }
    } else if (!issuedAt || issuedAt * 1000 < Date.now() - 5 * 60 * 1000) {
      throw new SocialAuthError('REAUTHENTICATE');
    }
    return user;
  }

  checkUser(user: any) {
    if (!user || !user.active || user.deletedAt || !user.inviteAcceptedAt) throw new SocialAuthError('ACCOUNT_UNAVAILABLE');
  }

  async start(provider: string, intent: string, browser: string, userId?: number, session?: string) {
    if (!['login', 'signup', 'link'].includes(intent)) throw new SocialAuthError('INVALID_INPUT');
    const verifier = randomToken();
    const nonce = randomToken();
    const state = await this.attempts.create('state', browser, {
      provider, intent, verifier, nonce, userId, session: session ? tokenHash(session) : null,
    });
    return authorizationURL(provider, state, verifier, nonce);
  }

  async callback(provider: string, state: string, code: string, browser: string, session: string) {
    const attempt = await this.attempts.consume(state, 'state', browser);
    if (attempt.provider !== provider) throw new SocialAuthError('EXPIRED');
    if (!code || code.length > 4096) throw new SocialAuthError('CANCELED');
    const profile = await exchangeProfile(provider, code, attempt.verifier, attempt.nonce);
    if (attempt.intent === 'link') {
      if (!session || tokenHash(session) !== attempt.session) throw new SocialAuthError('REAUTHENTICATE');
      await this.knex.transaction(async (trx) => {
        const user = await trx('users').where({ id: attempt.userId }).forUpdate().first();
        this.checkUser(user);
        const identity = await trx('socialIdentities').where({ provider, subject: profile.subject }).first();
        if (identity && identity.userId !== user.id) throw new SocialAuthError('ALREADY_CONNECTED');
        if (!identity) await trx('socialIdentities').insert({ provider, subject: profile.subject, userId: user.id });
      });
      return { linked: true };
    }
    const identity = await this.knex('socialIdentities').where({ provider, subject: profile.subject }).first();
    if (identity) {
      const user = await SystemUser.query().findById(identity.userId);
      this.checkUser(user);
      return { ticket: await this.attempts.create('handoff', browser, { userId: user.id }) };
    }
    if (profile.email) await this.checkCollision(profile.email);
    return { ticket: await this.attempts.create('profile', browser, profile), registration: true };
  }

  async checkCollision(email: string, trx = this.knex) {
    // Include invitations and deleted accounts: email never confers account access.
    if (await trx('users').whereRaw('LOWER(TRIM(EMAIL)) = ?', [email]).first()) {
      throw new SocialAuthError('SIGN_IN_TO_CONNECT');
    }
  }

  async profile(ticket: string, browser: string) {
    const profile = await this.attempts.consume(ticket, 'profile', browser);
    return { ticket: await this.attempts.create('profile', browser, profile),
      email: profile.email, firstName: profile.firstName, lastName: profile.lastName };
  }

  async complete(ticket: string, browser: string, values: { email: string; firstName: string; lastName: string }) {
    const profile: SocialProfile = await this.attempts.consume(ticket, 'profile', browser);
    await this.checkCollision(values.email);
    await this.signup.validateSignupRestrictions(values.email);
    if (!profile.emailVerified || profile.email !== values.email) {
      const verification = await this.attempts.create('email', browser, { profile, values });
      // Random 256-bit secret; only a hash is stored in the attempt record.
      await new Mail().setTo(values.email).setSubject('ABC Finance — verify your email')
        .setContent(`Enter this verification code in ABC Finance within 10 minutes: <strong>${verification}</strong>`).send();
      return { verificationRequired: true };
    }
    return this.register(profile, values, browser);
  }

  async verifyEmail(code: string, browser: string) {
    const { profile, values } = await this.attempts.consume(code, 'email', browser);
    return this.register(profile, values, browser);
  }

  private async register(profile: SocialProfile, values: any, browser: string) {
    const user = await this.knex.transaction(async (trx) => {
      return this.signup.signUp(values, { trx, provider: profile.provider, subject: profile.subject });
    });
    return { ticket: await this.attempts.create('handoff', browser, { userId: user.id }) };
  }

  async exchange(ticket: string, browser: string) {
    const { userId } = await this.attempts.consume(ticket, 'handoff', browser);
    const user = await SystemUser.query().findById(userId);
    this.checkUser(user);
    return this.signin.completeSignIn(user);
  }

  async connections(userId: number) {
    return this.knex('socialIdentities').where({ userId }).select('provider');
  }

  async hasPassword(userId: number) {
    const user = await SystemUser.query().findById(userId);
    return !!user?.password;
  }

  async disconnect(userId: number, provider: string) {
    await this.knex.transaction(async (trx) => {
      const user = await trx('users').where({ id: userId }).forUpdate().first();
      this.checkUser(user);
      const links = await trx('socialIdentities').where({ userId });
      const remaining = links.filter((link) => {
        if (link.provider === provider) return false;
        try { providerConfig(link.provider); return true; } catch (_) { return false; }
      });
      if (!user.password && !remaining.length) throw new SocialAuthError('LAST_LOGIN_METHOD');
      await trx('socialIdentities').where({ userId, provider }).delete();
    });
  }
}

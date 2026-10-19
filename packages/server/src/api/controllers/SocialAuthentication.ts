import { Router } from 'express';
import { Inject, Service } from 'typedi';
import { body, validationResult } from 'express-validator';
import JWTAuth from '@/api/middleware/jwtAuth';
import AttachCurrentTenantUser from '@/api/middleware/AttachCurrentTenantUser';
import { SocialAuth } from '@/services/Authentication/SocialAuth';
import { providerNames, providerConfig, frontendURL, randomToken, SocialAuthError } from '@/services/Authentication/SocialProviders';

const cookieName = 'abc_social_browser';
const cookie = (req, name) => {
  const value = (req.headers.cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  if (!value) return '';
  try { return decodeURIComponent(value.slice(name.length + 1)); } catch (_) { return ''; }
};

@Service()
export default class SocialAuthentication {
  @Inject() private social: SocialAuth;

  router() {
    const router = Router();
    router.use((req, res, next) => {
      res.set('Cache-Control', 'no-store');
      res.set('Referrer-Policy', 'no-referrer');
      if (req.method !== 'GET') {
        try {
          if (req.headers.origin !== frontendURL().origin || !req.is('application/json')) {
            return res.status(403).send({ errors: [{ type: 'INVALID_ORIGIN' }] });
          }
        } catch (_) { return res.status(503).send({ errors: [{ type: 'UNAVAILABLE' }] }); }
      }
      next();
    });
    router.get('/providers', this.handle(async (req, res) => {
      const providers = providerNames.filter((name) => { try { providerConfig(name); return true; } catch (_) { return false; } });
      res.send({ providers });
    }));
    router.post('/:provider/start', this.handle(async (req, res) => {
      const { provider } = req.params;
      providerConfig(provider);
      const intent = req.body.intent;
      if (!['login', 'signup'].includes(intent)) throw new SocialAuthError('INVALID_INPUT');
      res.send({ url: await this.social.start(provider, intent, this.browser(req, res)) });
    }));
    router.get('/:provider/callback', this.handle(async (req, res) => {
      const result = await this.social.callback(req.params.provider, req.query.state, req.query.code,
        cookie(req, cookieName), cookie(req, 'token'));
      const target = new URL(result.linked ? '/preferences/connected-accounts' : '/auth/social', frontendURL());
      target.hash = new URLSearchParams(result.linked ? { linked: 'true' } :
        { ticket: result.ticket, registration: String(!!result.registration) }).toString();
      res.redirect(303, target.toString());
    }, true));
    router.post('/profile', this.handle(async (req, res) => {
      res.send(await this.social.profile(req.body.ticket, cookie(req, cookieName)));
    }));
    router.post('/complete',
      body('email').isString().trim().isEmail().isLength({ max: 255 }),
      body('first_name').isString().trim().isLength({ min: 1, max: 255 }),
      body('last_name').isString().trim().isLength({ min: 1, max: 255 }),
      this.handle(async (req, res) => {
        if (!validationResult(req).isEmpty()) throw new SocialAuthError('INVALID_INPUT');
        res.send(await this.social.complete(req.body.ticket, cookie(req, cookieName), {
          email: req.body.email.toLowerCase(), firstName: req.body.first_name, lastName: req.body.last_name,
        }));
      }));
    router.post('/verify-email', this.handle(async (req, res) => {
      res.send(await this.social.verifyEmail(req.body.code, cookie(req, cookieName)));
    }));
    router.post('/exchange', this.handle(async (req, res) => {
      res.send(await this.social.exchange(req.body.ticket, cookie(req, cookieName)));
    }));
    router.use('/connections', JWTAuth, AttachCurrentTenantUser);
    router.get('/connections', this.handle(async (req, res) => {
      res.send({ connections: await this.social.connections(req.user.id), hasPassword: await this.social.hasPassword(req.user.id) });
    }));
    router.post('/connections/:provider', this.handle(async (req, res) => {
      providerConfig(req.params.provider);
      await this.social.freshUser(req.user.id, req.body.password, req.token.iat);
      res.send({ url: await this.social.start(req.params.provider, 'link', this.browser(req, res), req.user.id,
        req.headers['x-access-token']) });
    }));
    router.delete('/connections/:provider', this.handle(async (req, res) => {
      if (!providerNames.includes(req.params.provider)) throw new SocialAuthError('INVALID_INPUT');
      await this.social.freshUser(req.user.id, req.body.password, req.token.iat);
      await this.social.disconnect(req.user.id, req.params.provider);
      res.send({ success: true });
    }));
    return router;
  }

  private browser(req, res) {
    const current = cookie(req, cookieName);
    const token = /^[a-f0-9]{64}$/.test(current) ? current : randomToken();
    res.cookie(cookieName, token, { httpOnly: true, sameSite: 'lax', secure: frontendURL().protocol === 'https:',
      path: '/api/auth/social', maxAge: 10 * 60 * 1000 });
    return token;
  }

  private handle(action, redirect = false) {
    return async (req, res) => {
      try { await action(req, res); } catch (error) {
        // Provider HTTP errors can contain credentials; never forward or log their raw object.
        const code = error instanceof SocialAuthError ? error.code :
          error.errorType === 'EMAIL_EXISTS' || error.code === 'ER_DUP_ENTRY' || error.nativeError?.code === 'ER_DUP_ENTRY' ? 'SIGN_IN_TO_CONNECT' :
          ['SIGNUP_RESTRICTED', 'SIGNUP_RESTRICTED_NOT_ALLOWED'].includes(error.errorType) ? 'SIGNUP_RESTRICTED' : 'FAILED';
        if (redirect) {
          try {
            const target = new URL(cookie(req, 'token') ? '/preferences/connected-accounts' : '/auth/social', frontendURL());
            target.hash = new URLSearchParams({ error: code }).toString();
            return res.redirect(303, target.toString());
          } catch (_) { /* Configuration unavailable: return a sanitized error. */ }
        }
        res.status(400).send({ errors: [{ type: code }] });
      }
    };
  }
}

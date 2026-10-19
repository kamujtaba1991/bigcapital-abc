import { Inject, Service } from 'typedi';
import { randomToken, tokenHash, SocialAuthError } from './SocialProviders';

@Service()
export class SocialAttempts {
  @Inject('knex') private knex: any;

  async create(kind: string, browser: string, payload: any, trx = this.knex) {
    const token = randomToken();
    await trx('socialAttempts').where('expiresAt', '<', new Date()).delete();
    await trx('socialAttempts').insert({ id: tokenHash(token), browser: tokenHash(browser), kind,
      payload: JSON.stringify(payload), expiresAt: new Date(Date.now() + 10 * 60 * 1000) });
    return token;
  }

  async consume(token: string, kind: string, browser: string, trx?: any) {
    if (!/^[a-f0-9]{64}$/.test(token || '') || !/^[a-f0-9]{64}$/.test(browser || '')) {
      throw new SocialAuthError('EXPIRED');
    }
    const consume = async (db) => {
      const row = await db('socialAttempts').where({ id: tokenHash(token), kind, browser: tokenHash(browser) })
        .where('expiresAt', '>', new Date()).forUpdate().first();
      if (!row) throw new SocialAuthError('EXPIRED');
      await db('socialAttempts').where({ id: row.id }).delete();
      return JSON.parse(row.payload);
    };
    return trx ? consume(trx) : this.knex.transaction(consume);
  }
}

import { defaultTo, isEmpty, omit } from 'lodash';
import moment from 'moment';
import crypto from 'crypto';
import { ServiceError } from '@/exceptions';
import {
  IAuthSignedUpEventPayload,
  IAuthSigningUpEventPayload,
  IRegisterDTO,
  ISystemUser,
} from '@/interfaces';
import { ERRORS } from './_constants';
import { Inject } from 'typedi';
import { EventPublisher } from '@/lib/EventPublisher/EventPublisher';
import TenantsManagerService from '../Tenancy/TenantsManager';
import events from '@/subscribers/events';
import { hashPassword } from '@/utils';
import config from '@/config';
import { SystemUser } from '@/system/models';

export class AuthSignupService {
  @Inject()
  private eventPublisher: EventPublisher;

  @Inject('repositories')
  private sysRepositories: any;

  @Inject()
  private tenantsManager: TenantsManagerService;

  /**
   * Registers a new tenant with user from user input.
   * @throws {ServiceErrors}
   * @param {IRegisterDTO} signupDTO
   * @returns {Promise<ISystemUser>}
   */
  public async signUp(signupDTO: IRegisterDTO, social?: { trx: any; provider: string; subject: string }): Promise<ISystemUser> {
    return social ? this.createUser(signupDTO, social.trx, social)
      : SystemUser.knex().transaction((trx) => this.createUser(signupDTO, trx));
  }

  private async createUser(signupDTO: IRegisterDTO, trx: any, social?: { provider: string; subject: string }) {
    const { systemUserRepository } = this.sysRepositories;

    // Validates the signup disable restrictions.
    await this.validateSignupRestrictions(signupDTO.email);

    // Serialize registration without imposing global email uniqueness on company invitations.
    const id = crypto.createHash('sha256').update(signupDTO.email.trim().toLowerCase()).digest('hex');
    await trx('authSignupLocks').insert({ id }).onConflict('id').merge();
    await this.validateEmailUniqiness(signupDTO.email, trx, !!social);

    const hashedPassword = social ? null : await hashPassword(signupDTO.password);

    const verifyTokenCrypto = crypto.randomBytes(64).toString('hex');
    const verifiedEnabed = !social && defaultTo(config.signupConfirmation.enabled, false);
    const verifyToken = verifiedEnabed ? verifyTokenCrypto : '';
    const verified = !verifiedEnabed;

    const inviteAcceptedAt = moment().format('YYYY-MM-DD');

    // Triggers signin up event.
    await this.eventPublisher.emitAsync(events.auth.signingUp, {
      signupDTO,
    } as IAuthSigningUpEventPayload);

    const tenant = await this.tenantsManager.createTenant(trx);
    const userData = {
      ...omit(signupDTO, 'country'),
      verifyToken,
      verified,
      active: true,
      password: hashedPassword,
      tenantId: tenant.id,
      inviteAcceptedAt,
    };
    const registeredUser = await systemUserRepository.create(userData, trx);
    if (social) {
      await trx('socialIdentities').insert({
        provider: social.provider, subject: social.subject, userId: registeredUser.id,
      });
    }
    // Triggers signed up event.
    await this.eventPublisher.emitAsync(events.auth.signUp, {
      signupDTO,
      tenant,
      user: registeredUser,
      trx,
    } as IAuthSignedUpEventPayload);

    return registeredUser;
  }

  /**
   * Validates email uniqiness on the storage.
   * @throws {ServiceErrors}
   * @param  {string} email - Email address
   */
  private async validateEmailUniqiness(email: string, trx: any, includeDeleted: boolean) {
    const query = includeDeleted ? trx('users') : SystemUser.query(trx);
    const isEmailExists = await query.whereRaw('LOWER(TRIM(EMAIL)) = ?', [email.trim().toLowerCase()]).forUpdate().first();

    if (isEmailExists) {
      throw new ServiceError(ERRORS.EMAIL_EXISTS);
    }
  }

  /**
   * Validate sign-up disable restrictions.
   * @param {string} email
   */
  public async validateSignupRestrictions(email: string) {
    // Can't continue if the signup is not disabled.
    if (!config.signupRestrictions.disabled) return;

    // Validate the allowed email addresses and domains.
    if (
      !isEmpty(config.signupRestrictions.allowedEmails) ||
      !isEmpty(config.signupRestrictions.allowedDomains)
    ) {
      const emailDomain = email.split('@').pop();
      const isAllowedEmail =
        config.signupRestrictions.allowedEmails.indexOf(email) !== -1;

      const isAllowedDomain = config.signupRestrictions.allowedDomains.some(
        (domain) => emailDomain === domain
      );

      if (!isAllowedEmail && !isAllowedDomain) {
        throw new ServiceError(ERRORS.SIGNUP_RESTRICTED_NOT_ALLOWED);
      }
      // Throw error if the signup is disabled with no exceptions.
    } else {
      throw new ServiceError(ERRORS.SIGNUP_RESTRICTED);
    }
  }
}

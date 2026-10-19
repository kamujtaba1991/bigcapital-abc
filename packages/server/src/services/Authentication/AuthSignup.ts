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
import { SystemUser, Tenant } from '@/system/models';
import uniqid from 'uniqid';

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
    const { systemUserRepository } = this.sysRepositories;

    // Validates the signup disable restrictions.
    await this.validateSignupRestrictions(signupDTO.email);

    // Validates the given email uniqiness.
    await this.validateEmailUniqiness(signupDTO.email);

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

    const tenant = social
      ? await Tenant.query(social.trx).insert({ organizationId: uniqid() })
      : await this.tenantsManager.createTenant();
    const userData = {
      ...omit(signupDTO, 'country'),
      verifyToken,
      verified,
      active: true,
      password: hashedPassword,
      tenantId: tenant.id,
      inviteAcceptedAt,
    };
    const registeredUser = social
      ? await SystemUser.query(social.trx).insert(userData)
      : await systemUserRepository.create(userData);
    if (social) {
      await social.trx('socialIdentities').insert({
        provider: social.provider, subject: social.subject, userId: registeredUser.id,
      });
    }
    // Triggers signed up event.
    await this.eventPublisher.emitAsync(events.auth.signUp, {
      signupDTO,
      tenant,
      user: registeredUser,
      trx: social?.trx,
    } as IAuthSignedUpEventPayload);

    return registeredUser;
  }

  /**
   * Validates email uniqiness on the storage.
   * @throws {ServiceErrors}
   * @param  {string} email - Email address
   */
  private async validateEmailUniqiness(email: string) {
    const { systemUserRepository } = this.sysRepositories;
    const isEmailExists = await systemUserRepository.findOneByEmail(email);

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

import axios from 'axios';

export const providerHttp = axios.create({ timeout: 10000, maxRedirects: 0 });

export class SocialAuthError extends Error {
  constructor(public code: string) { super(code); }
}

export interface SocialProfile {
  provider: string;
  subject: string;
  email: string;
  emailVerified: boolean;
  firstName: string;
  lastName: string;
}

export interface ProviderConfig {
  clientId: string;
  secret: string;
  redirectUri: string;
}

export interface SocialProvider {
  clientIdEnv: string;
  secretEnv: string;
  authorizationEndpoint: string;
  scope: string;
  pkce: boolean;
  nonce: boolean;
  exchange(config: ProviderConfig, code: string, verifier: string, nonce: string): Promise<Partial<SocialProfile>>;
}

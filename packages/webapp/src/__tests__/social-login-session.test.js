import React from 'react';
import { render, fireEvent, cleanup, wait } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from 'react-query';
import useApiRequest from '@/hooks/useRequest';
import { useAuthLogin } from '@/hooks/query/authentication';
import * as state from '@/hooks/state';
import { setCookie } from '@/utils';

jest.mock('@/hooks/useRequest', () => ({ __esModule: true, default: jest.fn() }));
jest.mock('@/utils', () => ({ setCookie: jest.fn() }));
jest.mock('@/hooks/state', () => ({
  useSetAuthToken: jest.fn(), useSetAuthUserId: jest.fn(), useSetLocale: jest.fn(),
  useSetOrganizationId: jest.fn(), useSetTenantId: jest.fn(),
}));

function Login({ social, onSuccess }) {
  const { mutate } = useAuthLogin({ exchangeSocialTicket: social, onSuccess });
  return <button onClick={() => mutate(social ? 'one-use-ticket' : { crediential: 'a@example.com', password: 'password' })}>Sign in</button>;
}

test.each([false, true])('password/social exchange (%s) initializes the same secure app session before its callback', async (social) => {
  const originalLocation = Object.getOwnPropertyDescriptor(window, 'location');
  Object.defineProperty(window, 'location', { configurable: true, value: new URL('https://finance.example') });
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  Object.values(state).filter(jest.isMockFunction).forEach((hook) => hook.mockReturnValue(jest.fn()));
  const response = { data: { token: 'app-token', user: { id: 1 },
    tenant: { id: 2, organization_id: 'company', metadata: { language: 'en' } } } };
  const post = jest.fn().mockResolvedValue(response);
  useApiRequest.mockReturnValue({ post });
  const onSuccess = jest.fn();
  try {
    const screen = render(<QueryClientProvider client={client}><Login social={social} onSuccess={onSuccess} /></QueryClientProvider>);
    fireEvent.click(screen.getByText('Sign in'));
    await wait(() => expect(onSuccess).toHaveBeenCalledWith(response));
    expect(post).toHaveBeenCalledWith(social ? 'auth/social/exchange' : 'auth/login', social ? { ticket: 'one-use-ticket' }
      : { crediential: 'a@example.com', password: 'password' });
    expect(setCookie).toHaveBeenCalledWith('token', 'app-token', 60, true);
    expect(state.useSetAuthToken.mock.results[0].value).toHaveBeenCalledWith('app-token');
    expect(state.useSetOrganizationId.mock.results[0].value).toHaveBeenCalledWith('company');
    expect(state.useSetTenantId.mock.results[0].value).toHaveBeenCalledWith(2);
  } finally {
    cleanup(); client.clear(); Object.defineProperty(window, 'location', originalLocation);
  }
});

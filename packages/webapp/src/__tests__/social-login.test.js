import React from 'react';
import { render, fireEvent, cleanup, wait } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import useApiRequest from '@/hooks/useRequest';
import { useAuthLogin } from '@/hooks/query/authentication';
import Buttons from '@/containers/Authentication/SocialLoginButtons';
import SocialLogin from '@/containers/Authentication/SocialLogin';
import Connections from '@/containers/Preferences/ConnectedAccounts';

jest.mock('@/hooks/useRequest', () => ({ __esModule: true, default: jest.fn() }));
jest.mock('@/hooks/query/authentication', () => ({ useAuthLogin: jest.fn() }));
jest.mock('@/containers/Authentication/AuthInsider', () => ({ __esModule: true, default: ({ children }) => <div>{children}</div> }));
jest.mock('react-intl-universal', () => ({ __esModule: true, default: { get: (key, values = {}) => {
  const translations = require('../lang/en/index.json');
  return Object.entries(values).reduce((text, [name, value]) => text.replace(`{${name}}`, value), translations[key] || key);
} } }));
const mount = (component) => render(<MemoryRouter>{component}</MemoryRouter>);
afterEach(cleanup);

test('login shows only configured providers and recovers from provider failure', async () => {
  useApiRequest.mockReturnValue({ get: async () => ({ data: { providers: ['google'] } }),
    post: async () => { throw new Error('provider down'); } });
  const screen = mount(<Buttons intent="login" />);
  await wait(() => expect(screen.getByText('Continue with Google')).toBeTruthy());
  expect(screen.queryByText('Continue with Facebook')).toBeNull();
  fireEvent.click(screen.getByText('Continue with Google'));
  await wait(() => expect(screen.getByRole('alert').textContent).toMatch(/could not finish/));
  expect(screen.getByText('Continue with Google').closest('button').disabled).toBe(false);
});
test('callback collision explains explicit linking without exchanging a session', async () => {
  const exchange = jest.fn();
  useAuthLogin.mockReturnValue({ mutateAsync: exchange });
  window.history.replaceState(null, '', '/auth/social#error=SIGN_IN_TO_CONNECT');
  useApiRequest.mockReturnValue({ post: jest.fn() });
  const screen = mount(<SocialLogin />);
  await wait(() => expect(screen.getByRole('alert').textContent).toMatch(/Sign in to that account, then connect/));
  expect(exchange).not.toHaveBeenCalled();
  expect(window.location.hash).toBe('');
  expect(screen.getAllByText('Sign In')[0].getAttribute('href')).toBe('/auth/login');
});
test('registration rotates its ticket and requests email proof before exchanging a session', async () => {
  const exchange = jest.fn();
  useAuthLogin.mockReturnValue({ mutateAsync: exchange });
  window.history.replaceState(null, '', '/auth/social#ticket=one-use&registration=true');
  const post = jest.fn(async (url) => ({ data: url.endsWith('/profile')
    ? { ticket: 'rotated', email: 'a@example.com', first_name: 'A', last_name: 'B' }
    : { verification_required: true } }));
  useApiRequest.mockReturnValue({ post });
  const screen = mount(<SocialLogin />);
  await wait(() => expect(screen.getByLabelText('Email').value).toBe('a@example.com'));
  expect(screen.getByLabelText('Email').required).toBe(true);
  expect(window.location.hash).toBe('');
  fireEvent.submit(screen.container.querySelector('form'));
  await wait(() => expect(screen.getByLabelText('Email verification code')).toBeTruthy());
  expect(post.mock.calls[1][1].ticket).toBe('rotated');
  expect(exchange).not.toHaveBeenCalled();
});
test('personal settings shows own connections and requires a password before changes', async () => {
  window.history.replaceState(null, '', '/preferences/connected-accounts#linked=true');
  useApiRequest.mockReturnValue({ get: async (url) => ({ data: url.endsWith('/providers')
    ? { providers: ['google', 'x'] } : { connections: [{ provider: 'google' }], has_password: true } }) });
  const screen = mount(<Connections />);
  await wait(() => expect(screen.getByText(/Google — Connected/)).toBeTruthy());
  expect(screen.getByText(/Twitter\/X — Not connected/)).toBeTruthy();
  expect(screen.getByRole('status').textContent).toMatch(/Account connected/);
  const input = screen.getByLabelText('Confirm your current password to connect or disconnect an account');
  expect(input.type).toBe('password');
  expect(input.autocomplete).toBe('current-password');
  expect([...screen.container.querySelectorAll('button')].every((button) => button.disabled)).toBe(true);
  expect(window.location.hash).toBe('');
});

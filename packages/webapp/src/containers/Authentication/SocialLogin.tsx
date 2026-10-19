import React from 'react';
import { Button, Callout, FormGroup, InputGroup, Spinner } from '@blueprintjs/core';
import { Link } from 'react-router-dom';
import intl from 'react-intl-universal';
import useApiRequest from '@/hooks/useRequest';
import { useAuthLogin } from '@/hooks/query/authentication';
import AuthInsider from './AuthInsider';
import { socialError } from './SocialLoginButtons';

export default function SocialLogin() {
  const api = useApiRequest();
  const { mutateAsync: exchange } = useAuthLogin({ exchangeSocialTicket: true });
  const [values, setValues] = React.useState({ email: '', first_name: '', last_name: '' });
  const [ticket, setTicket] = React.useState('');
  const [code, setCode] = React.useState('');
  const [verify, setVerify] = React.useState(false);
  const [pending, setPending] = React.useState(true);
  const [error, setError] = React.useState('');
  const started = React.useRef(false);
  React.useEffect(() => {
    if (started.current) return;
    started.current = true;
    const params = new URLSearchParams(window.location.hash.slice(1));
    window.history.replaceState(null, '', window.location.pathname);
    const initialize = async () => {
      if (params.has('error')) throw new Error(params.get('error') || 'FAILED');
      if (!params.get('ticket')) throw new Error('EXPIRED');
      if (params.get('registration') !== 'true') {
        await exchange(params.get('ticket'));
        window.location.replace('/');
      } else {
        const res = await api.post('auth/social/profile', { ticket: params.get('ticket') });
        setTicket(res.data.ticket);
        setValues({ email: res.data.email, first_name: res.data.first_name, last_name: res.data.last_name });
        setPending(false);
      }
    };
    initialize().catch((err) => { setError(socialError(err)); setPending(false); });
  }, [api, exchange]);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setPending(true);
    setError('');
    try {
      const res = verify ? await api.post('auth/social/verify-email', { code: code.trim() })
        : await api.post('auth/social/complete', { ticket, ...values });
      if (res.data.verification_required) { setVerify(true); setPending(false); return; }
      await exchange(res.data.ticket);
      window.location.replace('/');
    } catch (err) { setError(socialError(err)); setPending(false); }
  };
  return <AuthInsider classNames={{}}><h1>{intl.get('social.finish_signup')}</h1>
    {error && <Callout intent="danger" role="alert">{error} <Link to="/auth/login">{intl.get('sign_in')}</Link></Callout>}
    {pending ? <Spinner aria-label={intl.get('social.loading')} /> :
      (ticket || verify) && <form onSubmit={submit}>
        {verify ? <>
          <p>{intl.get('social.email_sent')}</p>
          <FormGroup label={intl.get('social.verification_code')} labelFor="social-code">
            <InputGroup id="social-code" value={code} onChange={(e) => setCode(e.target.value)} required autoComplete="one-time-code" />
          </FormGroup>
        </> : (['email', 'first_name', 'last_name'] as const).map((field) => <FormGroup key={field} label={intl.get(field)} labelFor={`social-${field}`}>
          <InputGroup id={`social-${field}`} type={field === 'email' ? 'email' : 'text'} value={values[field]}
            onChange={(e) => setValues({ ...values, [field]: e.target.value })} required maxLength={255} />
        </FormGroup>)}
        <Button type="submit" intent="primary">{intl.get(verify ? 'social.verify_create' : 'social.create_company')}</Button>
      </form>}
    <p><Link to="/auth/login">{intl.get('social.cancel')}</Link></p>
  </AuthInsider>;
}

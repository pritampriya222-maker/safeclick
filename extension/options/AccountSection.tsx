/**
 * extension/options/AccountSection.tsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Phase 5: Optional "Create an Account" section for the Options page.
 *
 * Design principles:
 *   - Explicitly labeled as OPTIONAL — nothing in Phases 1–4 requires an account
 *   - Explains exactly what syncs (settings + submitted reports)
 *   - History sync is a SEPARATE, distinctly labeled, OFF-by-default toggle
 *   - Never conflates "basic account" with "history sync"
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  getAuthState,
  login,
  register,
  logout,
  onAuthStateChange,
  type AuthState,
} from '../shared/authClient';

type Mode = 'login' | 'register';

interface FieldError {
  email?: string;
  password?: string;
  general?: string;
}

export const AccountSection: React.FC = () => {
  const [authState, setAuthState] = useState<AuthState | null>(null);
  const [mode, setMode] = useState<Mode>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState<FieldError>({});
  const [loading, setLoading] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');

  // Load initial auth state
  useEffect(() => {
    getAuthState().then(setAuthState);
    const unsub = onAuthStateChange(setAuthState);
    return unsub;
  }, []);

  const validate = (): boolean => {
    const errs: FieldError = {};
    if (!email.includes('@')) errs.email = 'Enter a valid email address';
    if (password.length < 8) errs.password = 'Password must be at least 8 characters';
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!validate()) return;

      setLoading(true);
      setErrors({});
      setSuccessMsg('');

      const result = mode === 'login'
        ? await login(email, password)
        : await register(email, password);

      setLoading(false);

      if ('message' in result) {
        setErrors({ general: result.message });
      } else {
        setSuccessMsg(mode === 'login' ? 'Signed in successfully.' : 'Account created and signed in.');
        setEmail('');
        setPassword('');
      }
    },
    [email, password, mode],
  );

  const handleLogout = useCallback(async () => {
    setLoading(true);
    await logout();
    setLoading(false);
    setSuccessMsg('Signed out. Your local data and settings are unchanged.');
  }, []);

  // ── Logged-in state ──────────────────────────────────────────────────────────
  if (authState) {
    return (
      <section className="account-section account-section--signed-in" aria-labelledby="account-heading">
        <div className="account-section__header">
          <h3 id="account-heading" className="account-section__title">
            <span className="account-section__icon">☁️</span>
            Cloud Account
          </h3>
          <span className="account-section__badge account-section__badge--active">Active</span>
        </div>

        <div className="account-section__info">
          <p className="account-section__email">
            Signed in as <strong>{authState.email}</strong>
          </p>
          <div className="account-section__sync-info">
            <p className="account-section__sync-item account-section__sync-item--on">
              ✓ Settings sync — on
            </p>
            <p className="account-section__sync-item account-section__sync-item--on">
              ✓ Submitted threat reports — on
            </p>
          </div>

          <div className="account-section__history-note">
            <p className="account-section__history-label">
              📋 Browsing history sync
            </p>
            <p className="account-section__history-desc">
              Your local browsing history stays on this device by default.
              This is a separate opt-in that you can enable in Settings below.
            </p>
          </div>
        </div>

        {successMsg && (
          <p className="account-section__success" role="status">{successMsg}</p>
        )}

        <button
          className="account-section__btn account-section__btn--logout"
          onClick={handleLogout}
          disabled={loading}
          id="btn-account-logout"
          aria-label="Sign out of your SafeClick account"
        >
          {loading ? 'Signing out…' : 'Sign out'}
        </button>
      </section>
    );
  }

  // ── Logged-out state ─────────────────────────────────────────────────────────
  return (
    <section className="account-section" aria-labelledby="account-heading">
      <div className="account-section__header">
        <h3 id="account-heading" className="account-section__title">
          <span className="account-section__icon">☁️</span>
          Cloud Account
          <span className="account-section__optional">— optional</span>
        </h3>
      </div>

      <p className="account-section__desc">
        SafeClick works fully without an account. Creating one lets you:
      </p>
      <ul className="account-section__benefits">
        <li>Sync your settings across devices</li>
        <li>Submit phishing reports to help protect other users</li>
        <li>Optionally sync browsing history (separate toggle, off by default)</li>
      </ul>

      <div className="account-section__tabs" role="tablist">
        <button
          role="tab"
          aria-selected={mode === 'login'}
          className={`account-section__tab ${mode === 'login' ? 'account-section__tab--active' : ''}`}
          onClick={() => { setMode('login'); setErrors({}); setSuccessMsg(''); }}
          id="tab-login"
        >
          Sign in
        </button>
        <button
          role="tab"
          aria-selected={mode === 'register'}
          className={`account-section__tab ${mode === 'register' ? 'account-section__tab--active' : ''}`}
          onClick={() => { setMode('register'); setErrors({}); setSuccessMsg(''); }}
          id="tab-register"
        >
          Create account
        </button>
      </div>

      <form className="account-section__form" onSubmit={handleSubmit} noValidate>
        <div className="account-section__field">
          <label htmlFor="account-email" className="account-section__label">Email</label>
          <input
            id="account-email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className={`account-section__input ${errors.email ? 'account-section__input--error' : ''}`}
            placeholder="you@example.com"
            disabled={loading}
            aria-describedby={errors.email ? 'account-email-error' : undefined}
          />
          {errors.email && (
            <p id="account-email-error" className="account-section__field-error" role="alert">
              {errors.email}
            </p>
          )}
        </div>

        <div className="account-section__field">
          <label htmlFor="account-password" className="account-section__label">Password</label>
          <input
            id="account-password"
            type="password"
            autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={`account-section__input ${errors.password ? 'account-section__input--error' : ''}`}
            placeholder={mode === 'register' ? 'At least 8 characters' : ''}
            disabled={loading}
            aria-describedby={errors.password ? 'account-password-error' : undefined}
          />
          {errors.password && (
            <p id="account-password-error" className="account-section__field-error" role="alert">
              {errors.password}
            </p>
          )}
        </div>

        {errors.general && (
          <p className="account-section__general-error" role="alert">{errors.general}</p>
        )}
        {successMsg && (
          <p className="account-section__success" role="status">{successMsg}</p>
        )}

        <button
          type="submit"
          className="account-section__btn account-section__btn--primary"
          disabled={loading}
          id={`btn-account-${mode}`}
          aria-label={mode === 'login' ? 'Sign in to your SafeClick account' : 'Create a SafeClick account'}
        >
          {loading ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
        </button>
      </form>
    </section>
  );
};

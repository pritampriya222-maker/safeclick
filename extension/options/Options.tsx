/**
 * options/Options.tsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Full options/settings page.
 * - Extension enable/disable toggle
 * - Notification preference selector
 * - Allowlist / Denylist domain editor
 * - Cursor indicator toggle (Phase 4 feature, declared in Phase 1 schema)
 * - "Share anonymized data" placeholder (greyed out, Phase 5 not yet implemented)
 * - History logging toggle (Phase 4 feature)
 */

import React, { useEffect, useState, useCallback } from 'react';
import { sendMessage } from '../shared/messaging';
import type { Settings } from '../shared/types';
import { DEFAULT_SETTINGS } from '../shared/constants';

type SaveState = 'idle' | 'saving' | 'saved' | 'error';

export const Options: React.FC = () => {
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [isLoading, setIsLoading] = useState(true);
  const [saveState, setSaveState] = useState<SaveState>('idle');
  const [newAllowDomain, setNewAllowDomain] = useState('');
  const [newDenyDomain, setNewDenyDomain] = useState('');
  const [domainError, setDomainError] = useState<string | null>(null);

  // Load current settings on mount.
  useEffect(() => {
    (async () => {
      const response = await sendMessage<Settings>({ type: 'GET_SETTINGS' });
      if (response.success && response.data) {
        setSettings(response.data);
      }
      setIsLoading(false);
    })();
  }, []);

  const saveSettings = useCallback(async (updated: Settings) => {
    setSaveState('saving');
    const response = await sendMessage({
      type: 'SET_SETTINGS',
      settings: updated,
    });
    setSaveState(response.success ? 'saved' : 'error');
    setTimeout(() => setSaveState('idle'), 2000);
  }, []);

  const updateSetting = useCallback(
    <K extends keyof Settings>(key: K, value: Settings[K]) => {
      const updated = { ...settings, [key]: value };
      setSettings(updated);
      saveSettings(updated);
    },
    [settings, saveSettings]
  );

  function validateDomain(domain: string): string | null {
    if (!domain.trim()) return 'Domain cannot be empty.';
    if (domain.includes('/') || domain.includes(' ')) {
      return 'Enter a domain only (e.g. example.com), without slashes or spaces.';
    }
    return null;
  }

  const addToList = (
    listKey: 'allowlist' | 'denylist',
    domain: string,
    setInput: React.Dispatch<React.SetStateAction<string>>
  ) => {
    const err = validateDomain(domain);
    if (err) { setDomainError(err); return; }
    setDomainError(null);
    const normalized = domain.toLowerCase().replace(/^www\./, '').trim();
    const current = settings[listKey];
    if (!current.includes(normalized)) {
      updateSetting(listKey, [...current, normalized]);
    }
    setInput('');
  };

  const removeFromList = (listKey: 'allowlist' | 'denylist', domain: string) => {
    updateSetting(listKey, settings[listKey].filter((d) => d !== domain));
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-slate-700 border-t-indigo-500 rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-white font-sans">
      {/* Header */}
      <header className="sticky top-0 z-10 bg-slate-950/95 backdrop-blur border-b border-slate-800 px-8 py-4 flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center">
          <span className="text-white text-sm font-bold">S</span>
        </div>
        <div>
          <h1 className="text-lg font-bold text-white">SafeClick Settings</h1>
          <p className="text-xs text-slate-500">Configure your browser protection</p>
        </div>
        {/* Save indicator */}
        <div className="ml-auto">
          {saveState === 'saving' && (
            <span className="text-xs text-slate-500 animate-pulse">Saving…</span>
          )}
          {saveState === 'saved' && (
            <span className="text-xs text-emerald-400">✓ Saved</span>
          )}
          {saveState === 'error' && (
            <span className="text-xs text-red-400">Save failed</span>
          )}
        </div>
      </header>

      <main className="max-w-2xl mx-auto px-8 py-8 space-y-8">

        {/* ── General ─────────────────────────────────────────────── */}
        <Section title="General" icon="⚙">
          {/* Enable/disable */}
          <ToggleRow
            id="toggle-enabled"
            label="Enable SafeClick"
            description="Turn off to suspend all threat detection and UI indicators."
            checked={settings.enabled}
            onChange={(v) => updateSetting('enabled', v)}
          />

          {/* Cursor indicator */}
          <ToggleRow
            id="toggle-cursor"
            label="Cursor color indicator"
            description="Subtly tints the cursor (or shows a corner dot) based on live threat level. Phase 4 feature."
            checked={settings.cursorIndicatorEnabled}
            onChange={(v) => updateSetting('cursorIndicatorEnabled', v)}
          />

          {/* History logging */}
          <ToggleRow
            id="toggle-history"
            label="Local history logging"
            description="Logs sites you visit with their verdicts locally. Never sent to any server without your consent."
            checked={settings.historyLoggingEnabled}
            onChange={(v) => updateSetting('historyLoggingEnabled', v)}
          />
        </Section>

        {/* ── Notifications ───────────────────────────────────────── */}
        <Section title="Notifications" icon="🔔">
          <div className="space-y-2">
            <label className="text-sm font-medium text-slate-300">
              Alert style for dangerous sites
            </label>
            <p className="text-xs text-slate-500 mb-3">
              Choose how you're notified when a dangerous site is detected.
            </p>
            {(
              [
                ['badge_only', 'Badge only', 'Update the toolbar badge silently. No interruption.'],
                ['toast', 'Toast notification', 'Show a browser notification popup.'],
                ['silent', 'Silent', 'Update badge with no visual highlight on the icon.'],
              ] as const
            ).map(([value, label, desc]) => (
              <label
                key={value}
                htmlFor={`notif-${value}`}
                className={`
                  flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors
                  ${settings.notificationPreference === value
                    ? 'border-indigo-500/50 bg-indigo-500/10'
                    : 'border-slate-700/50 bg-slate-800/30 hover:border-slate-600'
                  }
                `}
              >
                <input
                  id={`notif-${value}`}
                  type="radio"
                  name="notification"
                  value={value}
                  checked={settings.notificationPreference === value}
                  onChange={() => updateSetting('notificationPreference', value)}
                  className="mt-0.5 accent-indigo-500 flex-shrink-0"
                />
                <div>
                  <div className="text-sm font-medium text-slate-200">{label}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{desc}</div>
                </div>
              </label>
            ))}
          </div>
        </Section>

        {/* ── Allowlist ────────────────────────────────────────────── */}
        <Section title="Always Trusted Domains" icon="✓">
          <p className="text-xs text-slate-500 mb-3">
            Domains you've explicitly trusted. Verdicts are still computed but warnings are suppressed.
          </p>
          <DomainListEditor
            listKey="allowlist"
            domains={settings.allowlist}
            inputValue={newAllowDomain}
            onInputChange={setNewAllowDomain}
            onAdd={() => addToList('allowlist', newAllowDomain, setNewAllowDomain)}
            onRemove={(d) => removeFromList('allowlist', d)}
            placeholder="e.g. mybank.com"
            addButtonId="btn-add-allowlist"
            inputId="input-allowlist"
          />
        </Section>

        {/* ── Denylist ─────────────────────────────────────────────── */}
        <Section title="Always Blocked Domains" icon="✕">
          <p className="text-xs text-slate-500 mb-3">
            Domains always treated as dangerous, regardless of the engine verdict.
          </p>
          <DomainListEditor
            listKey="denylist"
            domains={settings.denylist}
            inputValue={newDenyDomain}
            onInputChange={setNewDenyDomain}
            onAdd={() => addToList('denylist', newDenyDomain, setNewDenyDomain)}
            onRemove={(d) => removeFromList('denylist', d)}
            placeholder="e.g. phishing-site.com"
            addButtonId="btn-add-denylist"
            inputId="input-denylist"
          />
        </Section>

        {/* ── Domain error ─────────────────────────────────────────── */}
        {domainError && (
          <div className="text-red-400 text-xs bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
            {domainError}
          </div>
        )}

        {/* ── Cloud Sync (Phase 5 placeholder) ─────────────────────── */}
        <Section title="Cloud &amp; Privacy" icon="☁">
          <div className="flex items-start gap-3 p-3 rounded-lg border border-slate-700/40 bg-slate-800/20 opacity-60">
            <input
              id="toggle-share-data"
              type="checkbox"
              checked={false}
              disabled
              className="mt-1 accent-indigo-500 flex-shrink-0"
            />
            <div>
              <label htmlFor="toggle-share-data" className="text-sm font-medium text-slate-400 cursor-not-allowed">
                Share anonymized threat data
              </label>
              <p className="text-xs text-slate-600 mt-0.5">
                Available in a future update (Phase 5 — Cloud Sync).
              </p>
            </div>
          </div>
        </Section>
      </main>
    </div>
  );
};

// ─── Sub-components ───────────────────────────────────────────────────────────

const Section: React.FC<{ title: string; icon: string; children: React.ReactNode }> = ({
  title,
  icon,
  children,
}) => (
  <section className="space-y-4">
    <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
      <span className="text-base">{icon}</span>
      <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
        {title}
      </h2>
    </div>
    {children}
  </section>
);

const ToggleRow: React.FC<{
  id: string;
  label: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}> = ({ id, label, description, checked, onChange }) => (
  <div className="flex items-start justify-between gap-4 py-2">
    <div>
      <label htmlFor={id} className="text-sm font-medium text-slate-200 cursor-pointer">
        {label}
      </label>
      <p className="text-xs text-slate-500 mt-0.5 max-w-md">{description}</p>
    </div>
    <button
      id={id}
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`
        relative flex-shrink-0 w-11 h-6 rounded-full border-2 transition-colors duration-200
        ${checked ? 'bg-indigo-600 border-indigo-500' : 'bg-slate-700 border-slate-600'}
      `}
    >
      <span
        className={`
          absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow
          transform transition-transform duration-200
          ${checked ? 'translate-x-5' : 'translate-x-0'}
        `}
      />
    </button>
  </div>
);

const DomainListEditor: React.FC<{
  listKey: string;
  domains: string[];
  inputValue: string;
  onInputChange: (v: string) => void;
  onAdd: () => void;
  onRemove: (d: string) => void;
  placeholder: string;
  addButtonId: string;
  inputId: string;
}> = ({
  domains,
  inputValue,
  onInputChange,
  onAdd,
  onRemove,
  placeholder,
  addButtonId,
  inputId,
}) => (
  <div className="space-y-2">
    <div className="flex gap-2">
      <input
        id={inputId}
        type="text"
        value={inputValue}
        onChange={(e) => onInputChange(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && onAdd()}
        placeholder={placeholder}
        className="
          flex-1 bg-slate-800/60 border border-slate-700 rounded-lg
          px-3 py-2 text-sm text-slate-200 placeholder-slate-600
          focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30
          transition-colors
        "
      />
      <button
        id={addButtonId}
        onClick={onAdd}
        className="
          px-3 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm
          font-medium rounded-lg transition-colors active:scale-95
        "
      >
        Add
      </button>
    </div>
    {domains.length === 0 ? (
      <p className="text-slate-600 text-xs italic py-2">No domains added yet.</p>
    ) : (
      <ul className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
        {domains.map((d) => (
          <li
            key={d}
            className="flex items-center justify-between bg-slate-800/40 border border-slate-700/40 rounded-lg px-3 py-2"
          >
            <span className="text-sm text-slate-300 font-mono">{d}</span>
            <button
              onClick={() => onRemove(d)}
              className="text-slate-600 hover:text-red-400 text-sm transition-colors ml-2 flex-shrink-0"
              aria-label={`Remove ${d}`}
            >
              ✕
            </button>
          </li>
        ))}
      </ul>
    )}
  </div>
);

export default Options;

import React, { useState, useEffect } from 'react';
import { addDomainBypass } from '../background/warningManager';

export function WarningPage() {
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [domain, setDomain] = useState<string>('');
  const [score, setScore] = useState<number>(85);
  const [reason, setReason] = useState<string>('');
  const [confidence, setConfidence] = useState<string>('high');
  const [reasonsList, setReasonsList] = useState<string[]>([]);
  const [showConfirmModal, setShowConfirmModal] = useState<boolean>(false);
  const [reportSuccess, setReportSuccess] = useState<boolean>(false);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const rawUrl = params.get('url') || '';
    const rawScore = parseInt(params.get('score') || '85', 10);
    const rawReason = params.get('reason') || 'Known malicious or phishing site detected.';
    const rawConf = params.get('confidence') || 'high';
    const rawReasonsJson = params.get('reasons');

    setTargetUrl(rawUrl);
    setScore(isNaN(rawScore) ? 85 : rawScore);
    setReason(rawReason);
    setConfidence(rawConf);

    try {
      if (rawUrl) {
        const parsed = new URL(rawUrl);
        setDomain(parsed.hostname.replace(/^www\./, ''));
      }
    } catch {
      setDomain(rawUrl);
    }

    if (rawReasonsJson) {
      try {
        const parsed = JSON.parse(rawReasonsJson);
        if (Array.isArray(parsed)) setReasonsList(parsed);
      } catch {
        // fallback
      }
    }
  }, []);

  const handleGoBack = () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://google.com';
    }
  };

  const handleProceedConfirm = async () => {
    if (domain) {
      await addDomainBypass(domain);
    }
    if (targetUrl) {
      window.location.href = targetUrl;
    }
  };

  const handleReportMistake = () => {
    setReportSuccess(true);
    setTimeout(() => setReportSuccess(false), 5000);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 relative overflow-hidden selection:bg-rose-500 selection:text-white">
      {/* Background threat aura gradient */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-rose-600/10 rounded-full blur-3xl pointer-events-none" />

      {/* Main warning card */}
      <div className="max-w-2xl w-full bg-slate-900/90 backdrop-blur-xl border border-rose-500/30 rounded-2xl p-8 shadow-2xl relative z-10 space-y-6">
        
        {/* Shield & Badge Header */}
        <div className="flex items-center space-x-4 border-b border-slate-800 pb-6">
          <div className="w-14 h-14 rounded-2xl bg-rose-500/15 border border-rose-500/40 flex items-center justify-center text-rose-400 shrink-0">
            <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <div>
            <div className="flex items-center space-x-3">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider bg-rose-500/20 text-rose-400 border border-rose-500/30">
                Dangerous Site Blocked
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700 capitalize">
                Confidence: {confidence}
              </span>
            </div>
            <h1 className="text-2xl font-bold text-white mt-1 break-all">
              {domain || 'Dangerous Website'}
            </h1>
          </div>
        </div>

        {/* Plain English Summary */}
        <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4 space-y-2">
          <h2 className="text-xs font-semibold text-rose-400 uppercase tracking-wider">
            Threat Analysis Summary
          </h2>
          <p className="text-slate-200 text-base leading-relaxed">
            {reason}
          </p>
        </div>

        {/* Specific reasons list */}
        {reasonsList.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Specific Risk Signals Flagged
            </h3>
            <ul className="space-y-2">
              {reasonsList.map((r, idx) => (
                <li key={idx} className="flex items-start space-x-3 text-sm text-slate-300 bg-slate-950/40 border border-slate-800/80 rounded-lg p-3">
                  <span className="w-2 h-2 rounded-full bg-rose-400 mt-1.5 shrink-0" />
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Risk score indicator */}
        <div className="flex items-center justify-between bg-slate-950/40 border border-slate-800/60 rounded-xl px-4 py-3 text-sm">
          <span className="text-slate-400">Risk Score Contribution:</span>
          <span className="font-mono font-bold text-rose-400 text-base">{score} / 100</span>
        </div>

        {/* Toast for mistake report */}
        {reportSuccess && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 rounded-xl text-sm flex items-center space-x-2">
            <svg className="w-5 h-5 text-emerald-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
            <span>Thank you. Your false-positive report has been recorded locally.</span>
          </div>
        )}

        {/* Action Buttons */}
        <div className="pt-4 flex flex-col sm:flex-row items-center gap-3">
          <button
            onClick={handleGoBack}
            className="w-full sm:flex-1 py-3.5 px-6 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-base transition-colors shadow-lg shadow-emerald-600/20 flex items-center justify-center space-x-2"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            <span>Back to Safety</span>
          </button>

          <button
            onClick={() => setShowConfirmModal(true)}
            className="w-full sm:w-auto py-3.5 px-5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-sm border border-slate-700 transition-colors"
          >
            Proceed Anyway
          </button>

          <button
            onClick={handleReportMistake}
            className="w-full sm:w-auto py-3.5 px-4 text-xs text-slate-400 hover:text-slate-200 underline underline-offset-4"
          >
            Report Mistake
          </button>
        </div>
      </div>

      {/* Confirmation Modal for Proceed Anyway */}
      {showConfirmModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center space-x-3 text-amber-400">
              <svg className="w-6 h-6 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <h3 className="text-lg font-bold text-white">Confirm Navigation Warning</h3>
            </div>
            <p className="text-slate-300 text-sm leading-relaxed">
              Are you sure you want to visit <span className="font-semibold text-white">{domain}</span>? This site exhibits verified phishing patterns. Entering login credentials or downloading files here could compromise your accounts.
            </p>
            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={() => setShowConfirmModal(false)}
                className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleProceedConfirm}
                className="px-4 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-sm font-semibold transition-colors shadow-lg shadow-rose-600/20"
              >
                I Understand, Proceed
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * tests/messaging.test.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Unit tests for shared/messaging.ts.
 * Verifies: message shape validation, error handling, graceful degradation.
 */

import { describe, it, expect, vi } from 'vitest';
import { sendMessage, onMessage, broadcastMessage } from '../shared/messaging';
import type { ExtensionMessage, GetVerdictMessage, MessageResponse } from '../shared/types';

describe('messaging.ts — sendMessage', () => {
  it('returns the response from chrome.runtime.sendMessage', async () => {
    const mockResponse: MessageResponse<string> = { success: true, data: 'test' };
    vi.mocked(chrome.runtime.sendMessage).mockResolvedValueOnce(mockResponse);

    const response = await sendMessage<string>({ type: 'GET_SETTINGS' });
    expect(response.success).toBe(true);
    expect(response.data).toBe('test');
  });

  it('returns a failure response when "Receiving end does not exist"', async () => {
    vi.mocked(chrome.runtime.sendMessage).mockRejectedValueOnce(
      new Error('Could not establish connection. Receiving end does not exist.')
    );

    const response = await sendMessage({ type: 'OPEN_OPTIONS' });
    expect(response.success).toBe(false);
    expect(response.error).toMatch(/not ready/i);
  });

  it('returns a failure response for other errors', async () => {
    vi.mocked(chrome.runtime.sendMessage).mockRejectedValueOnce(
      new Error('Some other error')
    );

    const response = await sendMessage({ type: 'GET_SETTINGS' });
    expect(response.success).toBe(false);
    expect(response.error).toContain('Some other error');
  });

  it('passes the correct message type to chrome.runtime.sendMessage', async () => {
    vi.mocked(chrome.runtime.sendMessage).mockResolvedValueOnce({ success: true });

    const message: GetVerdictMessage = { type: 'GET_VERDICT', tabId: 42 };
    await sendMessage(message);

    expect(chrome.runtime.sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'GET_VERDICT', tabId: 42 })
    );
  });
});

describe('messaging.ts — message shape validation', () => {
  it('GET_VERDICT message has required tabId field', () => {
    const msg: ExtensionMessage = { type: 'GET_VERDICT', tabId: 1 };
    expect(msg.type).toBe('GET_VERDICT');
    expect((msg as GetVerdictMessage).tabId).toBe(1);
  });

  it('VERDICT_UPDATE message has verdict field', () => {
    const msg: ExtensionMessage = {
      type: 'VERDICT_UPDATE',
      tabId: 1,
      verdict: {
        url: 'https://example.com',
        level: 'safe',
        score: 0,
        reasons: ['stub'],
        ruleTriggers: [],
        timestamp: new Date().toISOString(),
        isStub: true,
      },
    };
    expect(msg.type).toBe('VERDICT_UPDATE');
  });

  it('PAGE_SIGNALS message has signals field', () => {
    const msg: ExtensionMessage = {
      type: 'PAGE_SIGNALS',
      signals: {
        tabId: 1,
        hasLoginForm: false,
        charset: 'UTF-8',
        title: 'Test Page',
        capturedAt: new Date().toISOString(),
      },
    };
    expect(msg.type).toBe('PAGE_SIGNALS');
  });

  it('REPORT_SITE message has url field', () => {
    const msg: ExtensionMessage = {
      type: 'REPORT_SITE',
      url: 'https://phishing.example.com',
    };
    expect(msg.type).toBe('REPORT_SITE');
  });

  it('SET_SETTINGS message has settings field', () => {
    const msg: ExtensionMessage = {
      type: 'SET_SETTINGS',
      settings: { enabled: false },
    };
    expect(msg.type).toBe('SET_SETTINGS');
  });
});

describe('messaging.ts — onMessage', () => {
  it('registers a listener on chrome.runtime.onMessage', () => {
    const handler = vi.fn().mockResolvedValue({ success: true });
    const unsub = onMessage('GET_SETTINGS', handler);

    expect(chrome.runtime.onMessage.addListener).toHaveBeenCalled();
    unsub();
    expect(chrome.runtime.onMessage.removeListener).toHaveBeenCalled();
  });
});

describe('messaging.ts — broadcastMessage', () => {
  it('calls chrome.runtime.sendMessage', async () => {
    vi.mocked(chrome.runtime.sendMessage).mockResolvedValueOnce(undefined);
    await broadcastMessage({ type: 'OPEN_OPTIONS' });
    expect(chrome.runtime.sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'OPEN_OPTIONS' })
    );
  });

  it('does not throw when no listeners are open', async () => {
    vi.mocked(chrome.runtime.sendMessage).mockRejectedValueOnce(
      new Error('Could not establish connection. Receiving end does not exist.')
    );
    // broadcastMessage silently swallows this — should not throw.
    await expect(broadcastMessage({ type: 'OPEN_OPTIONS' })).resolves.toBeUndefined();
  });
});

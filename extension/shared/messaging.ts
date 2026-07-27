/**
 * shared/messaging.ts
 * ─────────────────────────────────────────────────────────────────────────────
 * Typed wrapper around chrome.runtime.sendMessage / onMessage.
 * ALL inter-component communication (popup ↔ background, content ↔ background)
 * must go through this module. Never call chrome.runtime.sendMessage directly.
 *
 * Design decisions:
 * - Full TypeScript generics on message types and response types
 * - Handles the MV3 "receiving end does not exist" error gracefully
 * - Supports both one-shot messages and persistent listeners
 * - Tab-targeted messaging for background → content script direction
 */

import type {
  ExtensionMessage,
  MessageResponse,
  MessageType,
} from './types';

// ─── Sending Messages ─────────────────────────────────────────────────────────

/**
 * Send a message to the background service worker.
 * Popup and content scripts use this to talk to background.
 *
 * @returns The response from the background, or null if an error occurred.
 */
export async function sendMessage<TResponse = unknown>(
  message: ExtensionMessage
): Promise<MessageResponse<TResponse>> {
  try {
    const response = await chrome.runtime.sendMessage(message);
    return response as MessageResponse<TResponse>;
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);

    // This error is expected when the popup sends a message but no listener
    // is registered yet (e.g., during service worker startup).
    if (errMessage.includes('Receiving end does not exist')) {
      return {
        success: false,
        error: 'Background service worker not ready. Please try again.',
      };
    }

    console.warn('[SafeClick] sendMessage error:', errMessage);
    return { success: false, error: errMessage };
  }
}

/**
 * Send a message to a specific tab's content script.
 * Background service worker uses this to talk to content scripts.
 *
 * @param tabId - Target tab ID
 * @param message - The message to send
 */
export async function sendMessageToTab<TResponse = unknown>(
  tabId: number,
  message: ExtensionMessage
): Promise<MessageResponse<TResponse>> {
  try {
    const response = await chrome.tabs.sendMessage(tabId, message);
    return response as MessageResponse<TResponse>;
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    // Content script may not be injected yet on some pages — this is expected.
    console.debug(
      `[SafeClick] sendMessageToTab(${tabId}) error (may be expected):`,
      errMessage
    );
    return { success: false, error: errMessage };
  }
}

// ─── Receiving Messages ───────────────────────────────────────────────────────

type MessageHandler<TMessage extends ExtensionMessage, TResponse = unknown> = (
  message: TMessage,
  sender: chrome.runtime.MessageSender
) => Promise<MessageResponse<TResponse>> | MessageResponse<TResponse>;

/**
 * Register a typed message listener.
 * The callback must return a MessageResponse (sync or async).
 *
 * @example
 * onMessage('GET_VERDICT', async (msg, sender) => {
 *   const verdict = await getVerdict(msg.url);
 *   return { success: true, data: verdict };
 * });
 *
 * @returns Unsubscribe function — call it to remove the listener.
 */
export function onMessage<TMessage extends ExtensionMessage, TResponse = unknown>(
  type: MessageType,
  handler: MessageHandler<TMessage, TResponse>
): () => void {
  const listener = (
    message: ExtensionMessage,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: MessageResponse<TResponse>) => void
  ): boolean => {
    if (message.type !== type) return false;

    const result = handler(message as TMessage, sender);

    if (result instanceof Promise) {
      result.then(sendResponse).catch((err) => {
        console.error(`[SafeClick] Message handler error for ${type}:`, err);
        sendResponse({
          success: false,
          error: err instanceof Error ? err.message : String(err),
        });
      });
      // Return true to indicate we'll call sendResponse asynchronously.
      return true;
    }

    sendResponse(result);
    return false;
  };

  chrome.runtime.onMessage.addListener(listener);
  return () => chrome.runtime.onMessage.removeListener(listener);
}

/**
 * Register a catch-all message listener.
 * Use this when you need to handle multiple message types in one place
 * (e.g., the background service worker's main message router).
 *
 * @returns Unsubscribe function.
 */
export function onAnyMessage(
  handler: (
    message: ExtensionMessage,
    sender: chrome.runtime.MessageSender
  ) => Promise<MessageResponse> | MessageResponse | undefined
): () => void {
  const listener = (
    message: ExtensionMessage,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: MessageResponse) => void
  ): boolean => {
    const result = handler(message, sender);

    if (result === undefined) return false;

    if (result instanceof Promise) {
      result.then(sendResponse).catch((err) => {
        console.error('[SafeClick] onAnyMessage handler error:', err);
        sendResponse({
          success: false,
          error: err instanceof Error ? err.message : String(err),
        });
      });
      return true;
    }

    sendResponse(result);
    return false;
  };

  chrome.runtime.onMessage.addListener(listener);
  return () => chrome.runtime.onMessage.removeListener(listener);
}

// ─── Utility ──────────────────────────────────────────────────────────────────

/**
 * Broadcast a message to all extension contexts (all open popups, dashboards).
 * Background service worker uses this to push verdict updates.
 *
 * Note: This is a best-effort broadcast. If no popup is open, the message
 * is silently dropped — this is expected behavior.
 */
export async function broadcastMessage(message: ExtensionMessage): Promise<void> {
  try {
    await chrome.runtime.sendMessage(message);
  } catch {
    // Silently ignore — no listeners open is a normal state.
  }
}

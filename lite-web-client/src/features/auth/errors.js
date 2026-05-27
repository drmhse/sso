const CALLBACK_ERROR_MESSAGES = {
  session_expired: 'Your session expired before the sign-in flow completed. Start again to continue.',
  access_denied: 'Access was denied by the identity provider.',
  invalid_request: 'The sign-in request was incomplete or invalid.',
};

const RESPONSE_ERROR_MESSAGES = {
  'Invalid verification token': 'This verification link is invalid or expired.',
};

export function formatCallbackError(code) {
  if (!code) return 'Authentication failed.';

  const normalized = String(code).trim();
  return CALLBACK_ERROR_MESSAGES[normalized] || `Authentication failed: ${normalized.replace(/_/g, ' ')}.`;
}

export function formatResponseErrorPayload(payload, fallback) {
  if (!payload) return fallback;

  if (typeof payload === 'string') {
    const trimmed = payload.trim();
    if (!trimmed) return fallback;

    try {
      return formatResponseErrorPayload(JSON.parse(trimmed), fallback);
    } catch (error) {
      return trimmed;
    }
  }

  if (typeof payload === 'object') {
    if (typeof payload.error_description === 'string' && payload.error_description.trim()) {
      const normalized = payload.error_description.trim();
      return RESPONSE_ERROR_MESSAGES[normalized] || normalized;
    }
    if (typeof payload.error === 'string' && payload.error.trim()) {
      const normalized = payload.error.trim();
      return RESPONSE_ERROR_MESSAGES[normalized] || normalized;
    }
    if (typeof payload.message === 'string' && payload.message.trim()) {
      const normalized = payload.message.trim();
      return RESPONSE_ERROR_MESSAGES[normalized] || normalized;
    }
  }

  return fallback;
}

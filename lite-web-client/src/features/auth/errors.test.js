import { describe, expect, it } from 'vitest';
import { formatCallbackError, formatResponseErrorPayload } from '@/features/auth/errors';

describe('auth error helpers', () => {
  it('maps callback error codes to user-facing copy', () => {
    expect(formatCallbackError('session_expired')).toContain('session expired');
    expect(formatCallbackError('access_denied')).toContain('denied');
  });

  it('normalizes JSON error payloads into readable messages', () => {
    expect(
      formatResponseErrorPayload(
        '{"error":"Invalid verification token","error_code":"BAD_REQUEST"}',
        'fallback',
      ),
    ).toBe('This verification link is invalid or expired.');

    expect(
      formatResponseErrorPayload({ error_description: 'Custom identity provider error' }, 'fallback'),
    ).toBe('Custom identity provider error');
  });
});

import { describe, expect, it } from 'vitest';
import { buildScrubbedUrl } from '@/utils/urlSecurity';

describe('urlSecurity', () => {
  it('removes sensitive query parameters while keeping the rest of the URL intact', () => {
    const result = buildScrubbedUrl(
      'https://auth.example.com/callback?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&token=abc123&org=acme',
      { queryKeys: ['token'] },
    );

    expect(result).toBe('/callback?redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&org=acme');
  });

  it('removes sensitive fragment parameters while preserving unrelated hash state', () => {
    const result = buildScrubbedUrl(
      'https://auth.example.com/callback#access_token=jwt&refresh_token=refresh&tab=security',
      { hashKeys: ['access_token', 'refresh_token'] },
    );

    expect(result).toBe('/callback#tab=security');
  });
});

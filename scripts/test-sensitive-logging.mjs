import assert from 'node:assert/strict';
import test from 'node:test';

import { sensitiveTracingLines } from './check-sensitive-logging.mjs';

test('rejects credential and email values passed to tracing', () => {
  const source = `
tracing::info!(user_id = %user.id, "allowed");
tracing::warn!(email = %user.email, "forbidden");
tracing::error!("token failed: {}", access_token);
tracing::error!(recipient = %to_email, "forbidden");
tracing::info!(from = %config.from_email, "forbidden");
tracing::warn!(value = %smtp_password, "forbidden");
`;
  assert.deepEqual(sensitiveTracingLines(source), [3, 4, 5, 6, 7]);
});

test('does not mistake redacted message text or comments for values', () => {
  const source = `
// tracing::warn!(email = %user.email, "commented out");
tracing::warn!(user_id = %user.id, "Password reset email was rate limited");
tracing::info!(reason_recorded = reason.is_some(), r#"access_token not logged"#);
tracing::info!(has_auth = smtp_username.is_some(), "SMTP auth configured");
`;
  assert.deepEqual(sensitiveTracingLines(source), []);
});

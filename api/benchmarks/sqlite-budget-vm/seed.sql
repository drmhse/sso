PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

INSERT INTO users (
  id, email, is_platform_owner, password_hash, email_verified_at, created_at
) VALUES (
  '00000000-0000-4000-8000-000000000001',
  'benchmark-owner@loadtest.local',
  1,
  '$argon2id$v=19$m=19456,t=2,p=1$/LnJHdDf5R3JPTMKHPcPAg$0t0aIehS97rbDOSMwJS0suTRhBpMzuvTqzM3zsulR/E',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

INSERT INTO organizations (
  id, slug, name, owner_user_id, status, tier_id, approved_by, approved_at,
  created_at, updated_at
) VALUES (
  '00000000-0000-4000-8000-000000000002',
  'benchmark-org',
  'Benchmark Org',
  '00000000-0000-4000-8000-000000000001',
  'active',
  'tier_free',
  '00000000-0000-4000-8000-000000000001',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);

INSERT INTO users (
  id, email, is_platform_owner, password_hash, email_verified_at, created_at,
  updated_at, org_id
) VALUES (
  '00000000-0000-4000-8000-000000000003',
  'benchmark-user@loadtest.local',
  0,
  '$argon2id$v=19$m=19456,t=2,p=1$/4HAgZx9LJekb2OLnWCjXw$OgWS6C5BhgtygEtgHPugBdeqhRBBm3niT9NAB51Nc1w',
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP,
  '00000000-0000-4000-8000-000000000002'
);

INSERT INTO services (
  id, org_id, slug, name, service_type, client_id, client_secret_hash,
  redirect_uris, resource_uris, created_at
) VALUES (
  '00000000-0000-4000-8000-000000000004',
  '00000000-0000-4000-8000-000000000002',
  'benchmark-service',
  'Benchmark Service',
  'desktop',
  '00000000-0000-4000-8000-000000000005',
  'synthetic-benchmark-only',
  '["http://localhost:4000/callback"]',
  '["https://benchmark.local/api"]',
  CURRENT_TIMESTAMP
);

INSERT INTO memberships (id, org_id, user_id, role, created_at) VALUES (
  '00000000-0000-4000-8000-000000000006',
  '00000000-0000-4000-8000-000000000002',
  '00000000-0000-4000-8000-000000000001',
  'owner',
  CURRENT_TIMESTAMP
);

INSERT INTO identities (
  id, user_id, provider, provider_user_id, issuing_org_id,
  issuing_service_id, created_at
) VALUES (
  '00000000-0000-4000-8000-000000000009',
  '00000000-0000-4000-8000-000000000003',
  'password',
  'benchmark-user@loadtest.local',
  '00000000-0000-4000-8000-000000000002',
  '00000000-0000-4000-8000-000000000004',
  CURRENT_TIMESTAMP
);

INSERT INTO permissions (
  id, namespace, object_id, relation, subject_type, subject_id, created_at
) VALUES (
  '00000000-0000-4000-8000-000000000007',
  'organization',
  '00000000-0000-4000-8000-000000000002',
  'owner',
  'user',
  '00000000-0000-4000-8000-000000000001',
  CURRENT_TIMESTAMP
);

INSERT INTO plans (
  id, service_id, name, price_cents, currency, features, is_default, created_at
) VALUES (
  '00000000-0000-4000-8000-000000000008',
  '00000000-0000-4000-8000-000000000004',
  'free',
  0,
  'usd',
  '[]',
  1,
  CURRENT_TIMESTAMP
);

COMMIT;

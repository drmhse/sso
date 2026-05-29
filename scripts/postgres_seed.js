const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const argon2 = require('argon2');
const crypto = require('crypto');
const dotenv = require('dotenv');

// Load environment variables from api/.env.dev
const envPath = path.resolve(__dirname, '../api/.env.dev');
dotenv.config({ path: envPath });

const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5433,
    database: process.env.DB_NAME || 'sso_test',
    user: process.env.DB_USER || 'sso_test_user',
    password: process.env.DB_PASSWORD || 'sso_test_password',
});

const encryptionKey = process.env.ENCRYPTION_KEY;
if (!encryptionKey || encryptionKey.length !== 64) {
    console.error('Error: ENCRYPTION_KEY must be 64 hex characters (32 bytes)');
    process.exit(1);
}

const keyBytes = Buffer.from(encryptionKey, 'hex');

function encrypt(text) {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBytes, nonce);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Prepend nonce, then encrypted data, then tag (matching Rust implementation's storage if it includes tag)
    // Wait, rust aes_gcm usually appends tag to ciphertext
    return Buffer.concat([nonce, encrypted, tag]);
}

async function seed() {
    const seedData = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'seed_data.json'), 'utf8'));
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        console.log('🗑️ Clearing existing data...');
        // Delete in reverse order of dependencies
        await client.query('DELETE FROM subscriptions');
        await client.query('DELETE FROM api_keys');
        await client.query('DELETE FROM saml_signing_keys');
        await client.query('DELETE FROM organization_oauth_credentials');
        await client.query('DELETE FROM upstream_providers');
        await client.query('DELETE FROM verified_domains');
        await client.query('DELETE FROM memberships');
        await client.query('DELETE FROM plans');
        await client.query('DELETE FROM services');
        await client.query('DELETE FROM organizations');
        await client.query('DELETE FROM organization_tiers');
        await client.query('DELETE FROM user_totp_secrets');
        await client.query('DELETE FROM users');

        console.log('🌱 Seeding organization tiers...');
        for (const tier of seedData.tiers) {
            await client.query(
                'INSERT INTO organization_tiers (id, name, display_name, default_max_services, default_max_users, price_cents, currency, features, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())',
                [tier.id, tier.name, tier.display_name, tier.default_max_services, tier.default_max_users, tier.price_cents, tier.currency, tier.features]
            );
        }

        console.log('🌱 Seeding users...');
        const userToOrgOwner = new Map(); // Track which users are owners of which orgs
        for (const user of seedData.users) {
            const passwordHash = await argon2.hash(user.password);
            await client.query(
                'INSERT INTO users (id, email, password_hash, is_platform_owner, email_verified_at, created_at) VALUES ($1, $2, $3, $4, $5, NOW())',
                [user.id, user.email, passwordHash, user.is_platform_owner || false, user.email_verified ? new Date() : null]
            );

            if (user.memberships) {
                for (const membership of user.memberships) {
                    if (membership.role === 'owner') {
                        userToOrgOwner.set(membership.org_id, user.id);
                    }
                }
            }

            if (user.mfa_enabled) {
                const secret = 'JBSWY3DPEHPK3PXP'; // Example 16-char base32 secret
                const encryptedSecret = encrypt(secret);
                await client.query(
                    'INSERT INTO user_totp_secrets (id, user_id, secret_encrypted, encryption_key_id, enabled, created_at) VALUES ($1, $2, $3, $4, $5, NOW())',
                    [`totp_${Math.random().toString(36).substr(2, 9)}`, user.id, encryptedSecret, 'default', true]
                );
            }
        }

        console.log('🌱 Seeding organizations...');
        for (const org of seedData.organizations) {
            const ownerUserId = userToOrgOwner.get(org.id);
            if (!ownerUserId && org.status === 'active') {
                console.warn(`Warning: No owner found for active organization ${org.slug}`);
            }
            await client.query(
                'INSERT INTO organizations (id, slug, name, status, tier_id, custom_domain, domain_verified, owner_user_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())',
                [org.id, org.slug, org.name, org.status, org.tier_id, org.custom_domain || null, org.domain_verified || false, ownerUserId || seedData.users[0].id]
            );
        }

        console.log('🌱 Seeding memberships...');
        for (const user of seedData.users) {
            if (user.memberships) {
                for (const membership of user.memberships) {
                    const membershipId = `memb_${Math.random().toString(36).substr(2, 9)}`;
                    await client.query(
                        'INSERT INTO memberships (id, user_id, org_id, role, created_at) VALUES ($1, $2, $3, $4, NOW())',
                        [membershipId, user.id, membership.org_id, membership.role]
                    );
                }
            }
        }

        console.log('🌱 Seeding services...');
        const servicePlanMap = new Map(); // Store plan IDs created for each service
        for (const service of seedData.services) {
            // Hash the client secret using SHA-256 (Base64 encoded) to match API
            const clientSecretHash = crypto.createHash('sha256').update(service.client_secret || 'default_secret').digest('base64');

            const redirectUrisJson = service.redirect_uris ? JSON.stringify(Array.isArray(service.redirect_uris) ? service.redirect_uris : [service.redirect_uris]) : null;

            await client.query(
                'INSERT INTO services (id, org_id, slug, name, service_type, client_id, client_secret_hash, redirect_uris, saml_enabled, saml_entity_id, saml_acs_url, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())',
                [service.id, service.org_id, service.slug, service.name, service.service_type, service.client_id, clientSecretHash, redirectUrisJson, service.saml_enabled || false, service.saml_entity_id || null, service.saml_acs_url || null]
            );

            // Seed a default plan for each service (required by UI)
            const planId = `plan_${Math.random().toString(36).substr(2, 9)}`;
            await client.query(
                'INSERT INTO plans (id, service_id, name, price_cents, currency, features, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW())',
                [planId, service.id, 'free', 0, 'usd', '[]']
            );
            servicePlanMap.set(`${service.id}:free`, planId);
        }

        if (seedData.saml_signing_keys) {
            console.log('🌱 Seeding SAML signing keys...');
            for (const key of seedData.saml_signing_keys) {
                const encryptedPrivKey = encrypt(key.private_key);
                await client.query(
                    'INSERT INTO saml_signing_keys (id, service_id, private_key_encrypted, public_key, encryption_key_id, valid_from, valid_until, is_active, created_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL \'1 year\', $6, NOW())',
                    [key.id, key.service_id, encryptedPrivKey, key.public_key, 'default', true]
                );
            }
        }

        if (seedData.api_keys) {
            console.log('🌱 Seeding API keys...');
            for (const key of seedData.api_keys) {
                // Key hash in API is SHA-256 base64
                const keyHash = crypto.createHash('sha256').update(key.key).digest('base64');
                await client.query(
                    'INSERT INTO api_keys (id, service_id, name, prefix, key_hash, permissions, created_by, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())',
                    [key.id, key.service_id, key.name, key.prefix, keyHash, key.permissions, key.created_by]
                );
            }
        }

        if (seedData.subscriptions) {
            console.log('🌱 Seeding subscriptions...');
            for (const sub of seedData.subscriptions) {
                const planId = servicePlanMap.get(`${sub.service_id}:${sub.plan_slug}`);
                if (!planId) continue;
                await client.query(
                    'INSERT INTO subscriptions (id, user_id, service_id, plan_id, status, current_period_end, created_at) VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL \'1 month\', NOW())',
                    [sub.id, sub.user_id, sub.service_id, planId, 'active']
                );
            }
        }

        console.log('🌱 Seeding BYOO credentials...');
        if (seedData.byoo_credentials) {
            for (const cred of seedData.byoo_credentials) {
                const encryptedSecret = encrypt(cred.client_secret);
                await client.query(
                    'INSERT INTO organization_oauth_credentials (id, org_id, provider, client_id, client_secret_encrypted, encryption_key_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())',
                    [cred.id, cred.org_id, cred.provider, cred.client_id, encryptedSecret, 'default']
                );
            }
        }

        console.log('🌱 Seeding upstream providers...');
        if (seedData.upstream_providers) {
            for (const provider of seedData.upstream_providers) {
                const encryptedSecret = encrypt(provider.client_secret);
                await client.query(
                    'INSERT INTO upstream_providers (id, org_id, connection_id, name, provider_type, client_id, client_secret_encrypted, encryption_key_id, issuer, enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())',
                    [provider.id, provider.org_id, provider.connection_id, provider.name, provider.provider_type, provider.client_id, encryptedSecret, 'default', provider.issuer, provider.enabled]
                );
            }
        }

        console.log('🌱 Seeding verified domains...');
        if (seedData.verified_domains) {
            for (const domain of seedData.verified_domains) {
                await client.query(
                    'INSERT INTO verified_domains (id, org_id, domain, verified, verification_token, upstream_provider_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())',
                    [domain.id, domain.org_id, domain.domain, domain.verified, 'seed_token_123', domain.upstream_provider_id]
                );
            }
        }

        await client.query('COMMIT');
        console.log('✅ Seeding completed successfully!');
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Seeding failed:', error);
    } finally {
        client.release();
        await pool.end();
    }
}

seed();

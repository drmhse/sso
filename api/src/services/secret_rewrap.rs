//! Resumable, database-wide secret verification and key rewrap support.
//!
//! The operation is deliberately idempotent: each invocation scans from the
//! beginning, authenticates every encrypted value, and changes only values
//! that are not already protected by the active key. Committed batches are
//! therefore the durable checkpoint after an interruption.

use crate::{
    encryption::{EncryptionContext, EncryptionError, EncryptionService},
    entities::{
        connected_accounts, identities, organization_billing_credentials,
        organization_oauth_credentials, organizations, saml_signing_keys, siem_configs,
        upstream_providers, user_totp_secrets, webhooks,
    },
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set,
    TransactionTrait,
};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;

const DEFAULT_BATCH_SIZE: u64 = 100;
const MAX_BATCH_SIZE: u64 = 1_000;
const RUNTIME_READINESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Schema inventory maintained alongside the scanner. Hash-only values are
/// intentionally excluded because they are not decryptable/rewrappable.
pub const SECRET_INVENTORY: &[(&str, &[&str])] = &[
    ("organizations", &["smtp_password_encrypted"]),
    (
        "organization_billing_credentials",
        &["api_key_encrypted", "webhook_secret_encrypted"],
    ),
    (
        "organization_oauth_credentials",
        &["client_secret_encrypted"],
    ),
    ("upstream_providers", &["client_secret_encrypted"]),
    ("user_totp_secrets", &["secret_encrypted"]),
    ("saml_signing_keys", &["private_key_encrypted"]),
    (
        "identities",
        &["access_token_encrypted", "refresh_token_encrypted"],
    ),
    (
        "connected_accounts",
        &["access_token_encrypted", "refresh_token_encrypted"],
    ),
    ("siem_configs", &["api_key", "auth_header"]),
    ("webhooks", &["secret_encrypted"]),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewrapOptions {
    pub apply: bool,
    pub batch_size: u64,
    pub max_batches: Option<u64>,
}

impl Default for RewrapOptions {
    fn default() -> Self {
        Self {
            apply: false,
            batch_size: DEFAULT_BATCH_SIZE,
            max_batches: None,
        }
    }
}

impl RewrapOptions {
    pub fn parse(arguments: &[String]) -> Result<Self, RewrapError> {
        let mut options = Self::default();
        let mut requested_apply = None;
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "--apply" => {
                    if requested_apply == Some(false) {
                        return Err(RewrapError::InvalidOption(
                            "--apply and --dry-run are mutually exclusive".to_string(),
                        ));
                    }
                    requested_apply = Some(true);
                    options.apply = true;
                }
                "--dry-run" => {
                    if requested_apply == Some(true) {
                        return Err(RewrapError::InvalidOption(
                            "--apply and --dry-run are mutually exclusive".to_string(),
                        ));
                    }
                    requested_apply = Some(false);
                    options.apply = false;
                }
                "--batch-size" => {
                    index += 1;
                    options.batch_size = parse_positive_u64(arguments.get(index), "--batch-size")?;
                }
                "--max-batches" => {
                    index += 1;
                    options.max_batches =
                        Some(parse_positive_u64(arguments.get(index), "--max-batches")?);
                }
                "--help" | "-h" => return Err(RewrapError::HelpRequested),
                argument => {
                    return Err(RewrapError::InvalidOption(format!(
                        "unknown rewrap-secrets option: {argument}"
                    )))
                }
            }
            index += 1;
        }
        if options.batch_size > MAX_BATCH_SIZE {
            return Err(RewrapError::InvalidOption(format!(
                "--batch-size cannot exceed {MAX_BATCH_SIZE}"
            )));
        }
        Ok(options)
    }
}

fn parse_positive_u64(value: Option<&String>, option: &str) -> Result<u64, RewrapError> {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| RewrapError::InvalidOption(format!("{option} requires a positive integer")))
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TableReport {
    pub rows_scanned: u64,
    pub rows_changed: u64,
    pub secrets_rewrapped: u64,
    pub plaintext_values_migrated: u64,
    pub empty_sentinels_skipped: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RewrapReport {
    pub mode: &'static str,
    pub active_key_id: String,
    pub inventory_tables: usize,
    pub inventory_values: usize,
    pub complete: bool,
    pub batches_processed: u64,
    pub tables: BTreeMap<&'static str, TableReport>,
    pub warnings: Vec<&'static str>,
}

impl RewrapReport {
    fn new(service: &EncryptionService, apply: bool) -> Self {
        Self {
            mode: if apply { "apply" } else { "dry-run" },
            active_key_id: service.key_id().to_string(),
            inventory_tables: SECRET_INVENTORY.len(),
            inventory_values: SECRET_INVENTORY
                .iter()
                .map(|(_, fields)| fields.len())
                .sum(),
            complete: true,
            batches_processed: 0,
            tables: BTreeMap::new(),
            warnings: vec![
                "Keep every previous key configured until an apply run and a subsequent dry-run both complete successfully.",
                "Apply mode upgrades legacy and version 1 values to record-and-field-bound version 2 envelopes.",
                "Each update uses compare-and-swap predicates; concurrent secret changes abort the batch without being overwritten.",
            ],
        }
    }

    fn table(&mut self, name: &'static str) -> &mut TableReport {
        self.tables.entry(name).or_default()
    }

    pub fn rows_requiring_changes(&self) -> u64 {
        self.tables.values().map(|table| table.rows_changed).sum()
    }

    pub fn secrets_requiring_rewrap(&self) -> u64 {
        self.tables
            .values()
            .map(|table| table.secrets_rewrapped)
            .sum()
    }

    pub fn plaintext_values_requiring_migration(&self) -> u64 {
        self.tables
            .values()
            .map(|table| table.plaintext_values_migrated)
            .sum()
    }
}

#[derive(Debug, Error)]
pub enum RewrapError {
    #[error(
        "rewrap-secrets [--dry-run|--apply] [--batch-size 1-{MAX_BATCH_SIZE}] [--max-batches N]"
    )]
    HelpRequested,
    #[error("{0}")]
    InvalidOption(String),
    #[error("database operation failed: {0}")]
    Database(#[from] sea_orm::DbErr),
    #[error("cannot process {table} record {record_id} field {field}: {source}")]
    Ciphertext {
        table: &'static str,
        record_id: String,
        field: &'static str,
        #[source]
        source: EncryptionError,
    },
    #[error(
        "plaintext and encrypted values disagree for {table} record {record_id} field {field}"
    )]
    PlaintextConflict {
        table: &'static str,
        record_id: String,
        field: &'static str,
    },
    #[error("{table} record {record_id} field {field} is valid base64 but is not decryptable; it is ambiguous legacy plaintext or damaged ciphertext and was not modified")]
    AmbiguousTextSecret {
        table: &'static str,
        record_id: String,
        field: &'static str,
    },
    #[error("{table} record {record_id} has no {field}; the row cannot be used safely and was not modified")]
    MissingRequiredSecret {
        table: &'static str,
        record_id: String,
        field: &'static str,
    },
    #[error("concurrent modification detected for {table} record {record_id}; no stale rewrap value was written, rerun the command")]
    ConcurrentModification {
        table: &'static str,
        record_id: String,
    },
    #[error(
        "runtime startup refused: {rows_changed} rows require secret migration ({secrets_requiring_rewrap} ciphertext values need rewrap; {plaintext_values_requiring_migration} plaintext compatibility values need migration); stop every API/worker and run rewrap-secrets --apply followed by a complete dry-run"
    )]
    RuntimeRequiresRewrap {
        rows_changed: u64,
        secrets_requiring_rewrap: u64,
        plaintext_values_requiring_migration: u64,
    },
    #[error(
        "runtime startup refused: the read-only secret inventory did not complete within {seconds} seconds; verify database health, quiesce every other API/worker, and run rewrap-secrets --dry-run"
    )]
    RuntimeReadinessTimeout { seconds: u64 },
}

struct RunState<'a> {
    options: &'a RewrapOptions,
    report: RewrapReport,
}

impl RunState<'_> {
    fn begin_batch(&mut self) -> bool {
        if self
            .options
            .max_batches
            .is_some_and(|maximum| self.report.batches_processed >= maximum)
        {
            self.report.complete = false;
            return false;
        }
        self.report.batches_processed += 1;
        true
    }
}

fn ensure_cas(
    rows_affected: u64,
    table: &'static str,
    record_id: String,
) -> Result<(), RewrapError> {
    if rows_affected == 1 {
        Ok(())
    } else {
        Err(RewrapError::ConcurrentModification { table, record_id })
    }
}

struct CipherPlan {
    value: Vec<u8>,
    changed: bool,
}

fn plan_ciphertext(
    service: &EncryptionService,
    encrypted: &[u8],
    table: &'static str,
    record_id: &str,
    field: &'static str,
) -> Result<CipherPlan, RewrapError> {
    let value = service
        .rewrap_with_context(encrypted, EncryptionContext::new(table, record_id, field))
        .map_err(|source| RewrapError::Ciphertext {
            table,
            record_id: record_id.to_string(),
            field,
            source,
        })?;
    Ok(CipherPlan {
        changed: value != encrypted,
        value,
    })
}

fn plan_required_ciphertext(
    service: &EncryptionService,
    encrypted: &[u8],
    table: &'static str,
    record_id: &str,
    field: &'static str,
) -> Result<CipherPlan, RewrapError> {
    let context = EncryptionContext::new(table, record_id, field);
    let plaintext = service
        .decrypt_with_context(encrypted, context)
        .map_err(|source| RewrapError::Ciphertext {
            table,
            record_id: record_id.to_string(),
            field,
            source,
        })?;
    if plaintext.is_empty() {
        return Err(RewrapError::MissingRequiredSecret {
            table,
            record_id: record_id.to_string(),
            field,
        });
    }
    plan_ciphertext(service, encrypted, table, record_id, field)
}

#[derive(Debug)]
struct OptionalSecretPlan {
    encrypted: Option<Vec<u8>>,
    clear_plaintext: bool,
    ciphertext_changed: bool,
    ciphertext_rewrapped: bool,
    plaintext_migrated: bool,
}

fn plan_optional_secret(
    service: &EncryptionService,
    plaintext: Option<&str>,
    encrypted: Option<&[u8]>,
    table: &'static str,
    record_id: &str,
    field: &'static str,
) -> Result<OptionalSecretPlan, RewrapError> {
    match (plaintext, encrypted) {
        (None, None) => Ok(OptionalSecretPlan {
            encrypted: None,
            clear_plaintext: false,
            ciphertext_changed: false,
            ciphertext_rewrapped: false,
            plaintext_migrated: false,
        }),
        (None, Some(encrypted)) => {
            let plan = plan_ciphertext(service, encrypted, table, record_id, field)?;
            Ok(OptionalSecretPlan {
                encrypted: Some(plan.value),
                clear_plaintext: false,
                ciphertext_changed: plan.changed,
                ciphertext_rewrapped: plan.changed,
                plaintext_migrated: false,
            })
        }
        (Some(plaintext), None) => Ok(OptionalSecretPlan {
            encrypted: Some(
                service
                    .encrypt_with_context(
                        plaintext,
                        EncryptionContext::new(table, record_id, field),
                    )
                    .map_err(|source| RewrapError::Ciphertext {
                        table,
                        record_id: record_id.to_string(),
                        field,
                        source,
                    })?,
            ),
            clear_plaintext: true,
            ciphertext_changed: true,
            ciphertext_rewrapped: false,
            plaintext_migrated: true,
        }),
        (Some(plaintext), Some(encrypted)) => {
            let decrypted = service
                .decrypt_with_context(encrypted, EncryptionContext::new(table, record_id, field))
                .map_err(|source| RewrapError::Ciphertext {
                    table,
                    record_id: record_id.to_string(),
                    field,
                    source,
                })?;
            if decrypted != plaintext {
                return Err(RewrapError::PlaintextConflict {
                    table,
                    record_id: record_id.to_string(),
                    field,
                });
            }
            let plan = plan_ciphertext(service, encrypted, table, record_id, field)?;
            Ok(OptionalSecretPlan {
                encrypted: Some(plan.value),
                clear_plaintext: true,
                ciphertext_changed: plan.changed,
                ciphertext_rewrapped: plan.changed,
                plaintext_migrated: true,
            })
        }
    }
}

#[derive(Debug)]
struct TextSecretPlan {
    value: String,
    changed: bool,
    plaintext_migrated: bool,
}

fn plan_text_secret(
    service: &EncryptionService,
    stored: &str,
    record_id: &str,
    field: &'static str,
) -> Result<TextSecretPlan, RewrapError> {
    match BASE64.decode(stored) {
        Err(_) => {
            let encrypted = service
                .encrypt_with_context(
                    stored,
                    EncryptionContext::new("siem_configs", record_id, field),
                )
                .map_err(|source| RewrapError::Ciphertext {
                    table: "siem_configs",
                    record_id: record_id.to_string(),
                    field,
                    source,
                })?;
            Ok(TextSecretPlan {
                value: BASE64.encode(encrypted),
                changed: true,
                plaintext_migrated: true,
            })
        }
        Ok(encrypted) => {
            let rewrapped = match service.rewrap_with_context(
                &encrypted,
                EncryptionContext::new("siem_configs", record_id, field),
            ) {
                Ok(rewrapped) => rewrapped,
                Err(source) if encrypted.starts_with(b"AUTHOSCE") => {
                    return Err(RewrapError::Ciphertext {
                        table: "siem_configs",
                        record_id: record_id.to_string(),
                        field,
                        source,
                    });
                }
                Err(_) => {
                    return Err(RewrapError::AmbiguousTextSecret {
                        table: "siem_configs",
                        record_id: record_id.to_string(),
                        field,
                    });
                }
            };
            Ok(TextSecretPlan {
                changed: rewrapped != encrypted,
                value: BASE64.encode(rewrapped),
                plaintext_migrated: false,
            })
        }
    }
}

pub async fn run(
    database: &DatabaseConnection,
    service: &EncryptionService,
    options: &RewrapOptions,
) -> Result<RewrapReport, RewrapError> {
    let mut state = RunState {
        options,
        report: RewrapReport::new(service, options.apply),
    };

    if !process_organizations(database, service, &mut state).await?
        || !process_billing(database, service, &mut state).await?
        || !process_org_oauth(database, service, &mut state).await?
        || !process_upstream(database, service, &mut state).await?
        || !process_totp(database, service, &mut state).await?
        || !process_saml(database, service, &mut state).await?
        || !process_identities(database, service, &mut state).await?
        || !process_connected_accounts(database, service, &mut state).await?
        || !process_siem(database, service, &mut state).await?
        || !process_webhooks(database, service, &mut state).await?
    {
        state.report.complete = false;
    }
    Ok(state.report)
}

/// Authenticate the complete secret inventory before any API or worker starts.
///
/// Runtime startup is deliberately read-only here. Required changes must be
/// performed by the quiesced `rewrap-secrets --apply` maintenance command so a
/// serving process can never race migration with a background secret consumer.
pub async fn verify_runtime_ready(
    database: &DatabaseConnection,
    service: &EncryptionService,
) -> Result<RewrapReport, RewrapError> {
    verify_runtime_ready_with_timeout(database, service, RUNTIME_READINESS_TIMEOUT).await
}

async fn verify_runtime_ready_with_timeout(
    database: &DatabaseConnection,
    service: &EncryptionService,
    timeout: std::time::Duration,
) -> Result<RewrapReport, RewrapError> {
    let report = tokio::time::timeout(timeout, run(database, service, &RewrapOptions::default()))
        .await
        .map_err(|_| RewrapError::RuntimeReadinessTimeout {
            seconds: timeout.as_secs(),
        })??;
    let rows_changed = report.rows_requiring_changes();
    if rows_changed != 0 {
        return Err(RewrapError::RuntimeRequiresRewrap {
            rows_changed,
            secrets_requiring_rewrap: report.secrets_requiring_rewrap(),
            plaintext_values_requiring_migration: report.plaintext_values_requiring_migration(),
        });
    }
    Ok(report)
}

macro_rules! process_one_blob {
    ($function:ident, $module:ident, $table:literal, $field:ident, $field_column:ident, $key_field:ident, $key_column:ident, $field_name:literal) => {
        async fn $function(
            database: &DatabaseConnection,
            service: &EncryptionService,
            state: &mut RunState<'_>,
        ) -> Result<bool, RewrapError> {
            let mut cursor: Option<String> = None;
            loop {
                let mut query = $module::Entity::find();
                if let Some(cursor) = &cursor {
                    query = query.filter($module::Column::Id.gt(cursor.clone()));
                }
                let rows = query
                    .order_by_asc($module::Column::Id)
                    .limit(state.options.batch_size)
                    .all(database)
                    .await?;
                if rows.is_empty() {
                    return Ok(true);
                }
                cursor = Some(rows.last().expect("nonempty batch").id.clone());
                let mut plans = Vec::with_capacity(rows.len());
                for row in &rows {
                    let plan = plan_required_ciphertext(
                        service,
                        &row.$field,
                        $table,
                        &row.id,
                        $field_name,
                    )?;
                    let changed = plan.changed || row.$key_field != service.key_id();
                    plans.push((row.clone(), plan, changed));
                }
                if plans.iter().any(|(_, _, changed)| *changed) && !state.begin_batch() {
                    return Ok(false);
                }
                let table_report = state.report.table($table);
                table_report.rows_scanned += rows.len() as u64;
                table_report.rows_changed +=
                    plans.iter().filter(|(_, _, changed)| *changed).count() as u64;
                table_report.secrets_rewrapped +=
                    plans.iter().filter(|(_, plan, _)| plan.changed).count() as u64;
                if state.options.apply {
                    let transaction = database.begin().await?;
                    for (row, plan, changed) in plans {
                        if !changed {
                            continue;
                        }
                        let result = $module::Entity::update_many()
                            .set($module::ActiveModel {
                                $field: Set(plan.value),
                                $key_field: Set(service.key_id().to_string()),
                                ..Default::default()
                            })
                            .filter($module::Column::Id.eq(row.id.clone()))
                            .filter($module::Column::$field_column.eq(row.$field.clone()))
                            .filter($module::Column::$key_column.eq(row.$key_field.clone()))
                            .exec(&transaction)
                            .await?;
                        if result.rows_affected != 1 {
                            return Err(RewrapError::ConcurrentModification {
                                table: $table,
                                record_id: row.id,
                            });
                        }
                    }
                    transaction.commit().await?;
                }
            }
        }
    };
}

process_one_blob!(
    process_org_oauth,
    organization_oauth_credentials,
    "organization_oauth_credentials",
    client_secret_encrypted,
    ClientSecretEncrypted,
    encryption_key_id,
    EncryptionKeyId,
    "client_secret_encrypted"
);
process_one_blob!(
    process_totp,
    user_totp_secrets,
    "user_totp_secrets",
    secret_encrypted,
    SecretEncrypted,
    encryption_key_id,
    EncryptionKeyId,
    "secret_encrypted"
);
process_one_blob!(
    process_saml,
    saml_signing_keys,
    "saml_signing_keys",
    private_key_encrypted,
    PrivateKeyEncrypted,
    encryption_key_id,
    EncryptionKeyId,
    "private_key_encrypted"
);

async fn process_upstream(
    database: &DatabaseConnection,
    service: &EncryptionService,
    state: &mut RunState<'_>,
) -> Result<bool, RewrapError> {
    let mut cursor: Option<String> = None;
    loop {
        let mut query = upstream_providers::Entity::find();
        if let Some(cursor) = &cursor {
            query = query.filter(upstream_providers::Column::Id.gt(cursor.clone()));
        }
        let rows = query
            .order_by_asc(upstream_providers::Column::Id)
            .limit(state.options.batch_size)
            .all(database)
            .await?;
        if rows.is_empty() {
            return Ok(true);
        }
        cursor = Some(rows.last().expect("nonempty batch").id.clone());
        let empty_count = rows
            .iter()
            .filter(|row| row.client_secret_encrypted.is_empty())
            .count() as u64;
        let mut plans = Vec::new();
        for row in &rows {
            // An empty blob is the existing sentinel for SAML providers, which do
            // not have an OAuth client secret. OAuth/OIDC runtime clients are
            // confidential and must always have decryptable secret material.
            if row.client_secret_encrypted.is_empty() {
                if row.provider_type != "saml" {
                    return Err(RewrapError::MissingRequiredSecret {
                        table: "upstream_providers",
                        record_id: row.id.clone(),
                        field: "client_secret_encrypted",
                    });
                }
                continue;
            }
            let plan = if row.provider_type == "saml" {
                plan_ciphertext(
                    service,
                    &row.client_secret_encrypted,
                    "upstream_providers",
                    &row.id,
                    "client_secret_encrypted",
                )?
            } else {
                plan_required_ciphertext(
                    service,
                    &row.client_secret_encrypted,
                    "upstream_providers",
                    &row.id,
                    "client_secret_encrypted",
                )?
            };
            let changed = plan.changed || row.encryption_key_id != service.key_id();
            plans.push((row.clone(), plan, changed));
        }
        if plans.iter().any(|(_, _, changed)| *changed) && !state.begin_batch() {
            return Ok(false);
        }
        let report = state.report.table("upstream_providers");
        report.rows_scanned += rows.len() as u64;
        report.empty_sentinels_skipped += empty_count;
        report.rows_changed += plans.iter().filter(|(_, _, changed)| *changed).count() as u64;
        report.secrets_rewrapped += plans.iter().filter(|(_, plan, _)| plan.changed).count() as u64;
        if state.options.apply {
            let transaction = database.begin().await?;
            for (row, plan, changed) in plans {
                if !changed {
                    continue;
                }
                let result = upstream_providers::Entity::update_many()
                    .set(upstream_providers::ActiveModel {
                        client_secret_encrypted: Set(plan.value),
                        encryption_key_id: Set(service.key_id().to_string()),
                        ..Default::default()
                    })
                    .filter(upstream_providers::Column::Id.eq(row.id.clone()))
                    .filter(
                        upstream_providers::Column::ClientSecretEncrypted
                            .eq(row.client_secret_encrypted),
                    )
                    .filter(upstream_providers::Column::EncryptionKeyId.eq(row.encryption_key_id))
                    .exec(&transaction)
                    .await?;
                ensure_cas(result.rows_affected, "upstream_providers", row.id)?;
            }
            transaction.commit().await?;
        }
    }
}

async fn process_organizations(
    database: &DatabaseConnection,
    service: &EncryptionService,
    state: &mut RunState<'_>,
) -> Result<bool, RewrapError> {
    let mut cursor: Option<String> = None;
    loop {
        let mut query = organizations::Entity::find();
        if let Some(cursor) = &cursor {
            query = query.filter(organizations::Column::Id.gt(cursor.clone()));
        }
        let rows = query
            .order_by_asc(organizations::Column::Id)
            .limit(state.options.batch_size)
            .all(database)
            .await?;
        if rows.is_empty() {
            return Ok(true);
        }
        cursor = Some(rows.last().expect("nonempty batch").id.clone());
        let mut plans = Vec::new();
        for row in &rows {
            if let Some(encrypted) = row.smtp_password_encrypted.as_deref() {
                let plan = plan_ciphertext(
                    service,
                    encrypted,
                    "organizations",
                    &row.id,
                    "smtp_password_encrypted",
                )?;
                let changed =
                    plan.changed || row.smtp_encryption_key_id.as_deref() != Some(service.key_id());
                plans.push((row.clone(), plan, changed));
            }
        }
        if plans.iter().any(|(_, _, changed)| *changed) && !state.begin_batch() {
            return Ok(false);
        }
        let report = state.report.table("organizations");
        report.rows_scanned += rows.len() as u64;
        report.rows_changed += plans.iter().filter(|(_, _, changed)| *changed).count() as u64;
        report.secrets_rewrapped += plans.iter().filter(|(_, plan, _)| plan.changed).count() as u64;
        if state.options.apply {
            let transaction = database.begin().await?;
            for (row, plan, changed) in plans {
                if !changed {
                    continue;
                }
                let mut update = organizations::Entity::update_many()
                    .set(organizations::ActiveModel {
                        smtp_password_encrypted: Set(Some(plan.value)),
                        smtp_encryption_key_id: Set(Some(service.key_id().to_string())),
                        ..Default::default()
                    })
                    .filter(organizations::Column::Id.eq(row.id.clone()));
                update = match row.smtp_password_encrypted {
                    Some(value) => {
                        update.filter(organizations::Column::SmtpPasswordEncrypted.eq(value))
                    }
                    None => update.filter(organizations::Column::SmtpPasswordEncrypted.is_null()),
                };
                update = match row.smtp_encryption_key_id {
                    Some(value) => {
                        update.filter(organizations::Column::SmtpEncryptionKeyId.eq(value))
                    }
                    None => update.filter(organizations::Column::SmtpEncryptionKeyId.is_null()),
                };
                let result = update.exec(&transaction).await?;
                ensure_cas(result.rows_affected, "organizations", row.id)?;
            }
            transaction.commit().await?;
        }
    }
}

async fn process_billing(
    database: &DatabaseConnection,
    service: &EncryptionService,
    state: &mut RunState<'_>,
) -> Result<bool, RewrapError> {
    let mut cursor: Option<String> = None;
    loop {
        let mut query = organization_billing_credentials::Entity::find();
        if let Some(cursor) = &cursor {
            query = query.filter(organization_billing_credentials::Column::Id.gt(cursor.clone()));
        }
        let rows = query
            .order_by_asc(organization_billing_credentials::Column::Id)
            .limit(state.options.batch_size)
            .all(database)
            .await?;
        if rows.is_empty() {
            return Ok(true);
        }
        cursor = Some(rows.last().expect("nonempty batch").id.clone());
        let mut plans = Vec::new();
        for row in &rows {
            let api = plan_required_ciphertext(
                service,
                &row.api_key_encrypted,
                "organization_billing_credentials",
                &row.id,
                "api_key_encrypted",
            )?;
            let webhook = plan_required_ciphertext(
                service,
                &row.webhook_secret_encrypted,
                "organization_billing_credentials",
                &row.id,
                "webhook_secret_encrypted",
            )?;
            let changed =
                api.changed || webhook.changed || row.encryption_key_id != service.key_id();
            plans.push((row.clone(), api, webhook, changed));
        }
        if plans.iter().any(|(_, _, _, changed)| *changed) && !state.begin_batch() {
            return Ok(false);
        }
        let report = state.report.table("organization_billing_credentials");
        report.rows_scanned += rows.len() as u64;
        report.rows_changed += plans.iter().filter(|(_, _, _, changed)| *changed).count() as u64;
        report.secrets_rewrapped += plans
            .iter()
            .map(|(_, api, webhook, _)| u64::from(api.changed) + u64::from(webhook.changed))
            .sum::<u64>();
        if state.options.apply {
            let transaction = database.begin().await?;
            for (row, api, webhook, changed) in plans {
                if !changed {
                    continue;
                }
                let result = organization_billing_credentials::Entity::update_many()
                    .set(organization_billing_credentials::ActiveModel {
                        api_key_encrypted: Set(api.value),
                        webhook_secret_encrypted: Set(webhook.value),
                        encryption_key_id: Set(service.key_id().to_string()),
                        ..Default::default()
                    })
                    .filter(organization_billing_credentials::Column::Id.eq(row.id.clone()))
                    .filter(
                        organization_billing_credentials::Column::ApiKeyEncrypted
                            .eq(row.api_key_encrypted),
                    )
                    .filter(
                        organization_billing_credentials::Column::WebhookSecretEncrypted
                            .eq(row.webhook_secret_encrypted),
                    )
                    .filter(
                        organization_billing_credentials::Column::EncryptionKeyId
                            .eq(row.encryption_key_id),
                    )
                    .exec(&transaction)
                    .await?;
                ensure_cas(
                    result.rows_affected,
                    "organization_billing_credentials",
                    row.id,
                )?;
            }
            transaction.commit().await?;
        }
    }
}

macro_rules! process_oauth_compat {
    ($function:ident, $module:ident, $table:literal) => {
        async fn $function(
            database: &DatabaseConnection,
            service: &EncryptionService,
            state: &mut RunState<'_>,
        ) -> Result<bool, RewrapError> {
            let mut cursor: Option<String> = None;
            loop {
                let mut query = $module::Entity::find();
                if let Some(cursor) = &cursor {
                    query = query.filter($module::Column::Id.gt(cursor.clone()));
                }
                let rows = query
                    .order_by_asc($module::Column::Id)
                    .limit(state.options.batch_size)
                    .all(database)
                    .await?;
                if rows.is_empty() {
                    return Ok(true);
                }
                cursor = Some(rows.last().expect("nonempty batch").id.clone());
                let mut plans = Vec::new();
                for row in &rows {
                    let access = plan_optional_secret(
                        service,
                        row.access_token.as_deref(),
                        row.access_token_encrypted.as_deref(),
                        $table,
                        &row.id,
                        "access_token_encrypted",
                    )?;
                    let refresh = plan_optional_secret(
                        service,
                        row.refresh_token.as_deref(),
                        row.refresh_token_encrypted.as_deref(),
                        $table,
                        &row.id,
                        "refresh_token_encrypted",
                    )?;
                    let has_encrypted = access.encrypted.is_some() || refresh.encrypted.is_some();
                    let changed = access.clear_plaintext
                        || refresh.clear_plaintext
                        || access.ciphertext_changed
                        || refresh.ciphertext_changed
                        || (has_encrypted
                            && row.encryption_key_id.as_deref() != Some(service.key_id()));
                    plans.push((row.clone(), access, refresh, changed));
                }
                if plans.iter().any(|(_, _, _, changed)| *changed) && !state.begin_batch() {
                    return Ok(false);
                }
                let report = state.report.table($table);
                report.rows_scanned += rows.len() as u64;
                report.rows_changed +=
                    plans.iter().filter(|(_, _, _, changed)| *changed).count() as u64;
                report.secrets_rewrapped += plans
                    .iter()
                    .map(|(_, access, refresh, _)| {
                        u64::from(access.ciphertext_rewrapped)
                            + u64::from(refresh.ciphertext_rewrapped)
                    })
                    .sum::<u64>();
                report.plaintext_values_migrated += plans
                    .iter()
                    .map(|(_, access, refresh, _)| {
                        u64::from(access.plaintext_migrated) + u64::from(refresh.plaintext_migrated)
                    })
                    .sum::<u64>();
                if state.options.apply {
                    let transaction = database.begin().await?;
                    for (row, access, refresh, changed) in plans {
                        if !changed {
                            continue;
                        }
                        let original_access = row.access_token.clone();
                        let original_refresh = row.refresh_token.clone();
                        let original_access_encrypted = row.access_token_encrypted.clone();
                        let original_refresh_encrypted = row.refresh_token_encrypted.clone();
                        let original_key_id = row.encryption_key_id.clone();
                        let mut active: $module::ActiveModel = Default::default();
                        if access.clear_plaintext {
                            active.access_token = Set(None);
                        }
                        if refresh.clear_plaintext {
                            active.refresh_token = Set(None);
                        }
                        active.access_token_encrypted = Set(access.encrypted);
                        active.refresh_token_encrypted = Set(refresh.encrypted);
                        if active.access_token_encrypted.as_ref().is_some()
                            || active.refresh_token_encrypted.as_ref().is_some()
                        {
                            active.encryption_key_id = Set(Some(service.key_id().to_string()));
                        }
                        let mut update = $module::Entity::update_many()
                            .set(active)
                            .filter($module::Column::Id.eq(row.id.clone()));
                        update = match original_access {
                            Some(value) => update.filter($module::Column::AccessToken.eq(value)),
                            None => update.filter($module::Column::AccessToken.is_null()),
                        };
                        update = match original_refresh {
                            Some(value) => update.filter($module::Column::RefreshToken.eq(value)),
                            None => update.filter($module::Column::RefreshToken.is_null()),
                        };
                        update = match original_access_encrypted {
                            Some(value) => {
                                update.filter($module::Column::AccessTokenEncrypted.eq(value))
                            }
                            None => update.filter($module::Column::AccessTokenEncrypted.is_null()),
                        };
                        update = match original_refresh_encrypted {
                            Some(value) => {
                                update.filter($module::Column::RefreshTokenEncrypted.eq(value))
                            }
                            None => update.filter($module::Column::RefreshTokenEncrypted.is_null()),
                        };
                        update = match original_key_id {
                            Some(value) => {
                                update.filter($module::Column::EncryptionKeyId.eq(value))
                            }
                            None => update.filter($module::Column::EncryptionKeyId.is_null()),
                        };
                        let result = update.exec(&transaction).await?;
                        ensure_cas(result.rows_affected, $table, row.id)?;
                    }
                    transaction.commit().await?;
                }
            }
        }
    };
}

process_oauth_compat!(process_identities, identities, "identities");
process_oauth_compat!(
    process_connected_accounts,
    connected_accounts,
    "connected_accounts"
);

async fn process_siem(
    database: &DatabaseConnection,
    service: &EncryptionService,
    state: &mut RunState<'_>,
) -> Result<bool, RewrapError> {
    let mut cursor: Option<String> = None;
    loop {
        let mut query = siem_configs::Entity::find();
        if let Some(cursor) = &cursor {
            query = query.filter(siem_configs::Column::Id.gt(cursor.clone()));
        }
        let rows = query
            .order_by_asc(siem_configs::Column::Id)
            .limit(state.options.batch_size)
            .all(database)
            .await?;
        if rows.is_empty() {
            return Ok(true);
        }
        cursor = Some(rows.last().expect("nonempty batch").id.clone());
        let mut plans = Vec::new();
        for row in &rows {
            let api = row
                .api_key
                .as_deref()
                .map(|stored| plan_text_secret(service, stored, &row.id, "api_key"))
                .transpose()?;
            let auth = row
                .auth_header
                .as_deref()
                .map(|stored| plan_text_secret(service, stored, &row.id, "auth_header"))
                .transpose()?;
            let changed = api.as_ref().is_some_and(|plan| plan.changed)
                || auth.as_ref().is_some_and(|plan| plan.changed);
            plans.push((row.clone(), api, auth, changed));
        }
        if plans.iter().any(|(_, _, _, changed)| *changed) && !state.begin_batch() {
            return Ok(false);
        }
        let report = state.report.table("siem_configs");
        report.rows_scanned += rows.len() as u64;
        report.rows_changed += plans.iter().filter(|(_, _, _, changed)| *changed).count() as u64;
        report.secrets_rewrapped += plans
            .iter()
            .map(|(_, api, auth, _)| {
                u64::from(
                    api.as_ref()
                        .is_some_and(|plan| plan.changed && !plan.plaintext_migrated),
                ) + u64::from(
                    auth.as_ref()
                        .is_some_and(|plan| plan.changed && !plan.plaintext_migrated),
                )
            })
            .sum::<u64>();
        report.plaintext_values_migrated += plans
            .iter()
            .map(|(_, api, auth, _)| {
                u64::from(api.as_ref().is_some_and(|plan| plan.plaintext_migrated))
                    + u64::from(auth.as_ref().is_some_and(|plan| plan.plaintext_migrated))
            })
            .sum::<u64>();
        if state.options.apply {
            let transaction = database.begin().await?;
            for (row, api, auth, changed) in plans {
                if !changed {
                    continue;
                }
                let original_api_key = row.api_key.clone();
                let original_auth_header = row.auth_header.clone();
                let mut active: siem_configs::ActiveModel = Default::default();
                if let Some(api) = api {
                    active.api_key = Set(Some(api.value));
                }
                if let Some(auth) = auth {
                    active.auth_header = Set(Some(auth.value));
                }
                let mut update = siem_configs::Entity::update_many()
                    .set(active)
                    .filter(siem_configs::Column::Id.eq(row.id.clone()));
                update = match original_api_key {
                    Some(value) => update.filter(siem_configs::Column::ApiKey.eq(value)),
                    None => update.filter(siem_configs::Column::ApiKey.is_null()),
                };
                update = match original_auth_header {
                    Some(value) => update.filter(siem_configs::Column::AuthHeader.eq(value)),
                    None => update.filter(siem_configs::Column::AuthHeader.is_null()),
                };
                let result = update.exec(&transaction).await?;
                ensure_cas(result.rows_affected, "siem_configs", row.id)?;
            }
            transaction.commit().await?;
        }
    }
}

async fn process_webhooks(
    database: &DatabaseConnection,
    service: &EncryptionService,
    state: &mut RunState<'_>,
) -> Result<bool, RewrapError> {
    let mut cursor: Option<String> = None;
    loop {
        let mut query = webhooks::Entity::find();
        if let Some(cursor) = &cursor {
            query = query.filter(webhooks::Column::Id.gt(cursor.clone()));
        }
        let rows = query
            .order_by_asc(webhooks::Column::Id)
            .limit(state.options.batch_size)
            .all(database)
            .await?;
        if rows.is_empty() {
            return Ok(true);
        }
        cursor = Some(rows.last().expect("nonempty batch").id.clone());
        let mut plans = Vec::new();
        for row in &rows {
            let plaintext = (!row.secret.is_empty()).then_some(row.secret.as_str());
            if plaintext.is_none() && row.secret_encrypted.is_none() {
                return Err(RewrapError::MissingRequiredSecret {
                    table: "webhooks",
                    record_id: row.id.clone(),
                    field: "secret_encrypted",
                });
            }
            let plan = if let Some(encrypted) = row.secret_encrypted.as_deref() {
                let required = plan_required_ciphertext(
                    service,
                    encrypted,
                    "webhooks",
                    &row.id,
                    "secret_encrypted",
                )?;
                if let Some(plaintext) = plaintext {
                    let decrypted = service
                        .decrypt_with_context(
                            encrypted,
                            EncryptionContext::new("webhooks", &row.id, "secret_encrypted"),
                        )
                        .map_err(|source| RewrapError::Ciphertext {
                            table: "webhooks",
                            record_id: row.id.clone(),
                            field: "secret_encrypted",
                            source,
                        })?;
                    if decrypted != plaintext {
                        return Err(RewrapError::PlaintextConflict {
                            table: "webhooks",
                            record_id: row.id.clone(),
                            field: "secret_encrypted",
                        });
                    }
                }
                OptionalSecretPlan {
                    encrypted: Some(required.value),
                    clear_plaintext: plaintext.is_some(),
                    ciphertext_changed: required.changed,
                    ciphertext_rewrapped: required.changed,
                    plaintext_migrated: plaintext.is_some(),
                }
            } else {
                plan_optional_secret(
                    service,
                    plaintext,
                    None,
                    "webhooks",
                    &row.id,
                    "secret_encrypted",
                )?
            };
            let changed = plan.clear_plaintext
                || plan.ciphertext_changed
                || (plan.encrypted.is_some()
                    && row.encryption_key_id.as_deref() != Some(service.key_id()));
            plans.push((row.clone(), plan, changed));
        }
        if plans.iter().any(|(_, _, changed)| *changed) && !state.begin_batch() {
            return Ok(false);
        }
        let report = state.report.table("webhooks");
        report.rows_scanned += rows.len() as u64;
        report.rows_changed += plans.iter().filter(|(_, _, changed)| *changed).count() as u64;
        report.secrets_rewrapped += plans
            .iter()
            .filter(|(_, plan, _)| plan.ciphertext_rewrapped)
            .count() as u64;
        report.plaintext_values_migrated += plans
            .iter()
            .filter(|(_, plan, _)| plan.plaintext_migrated)
            .count() as u64;
        if state.options.apply {
            let transaction = database.begin().await?;
            for (row, plan, changed) in plans {
                if !changed {
                    continue;
                }
                let original_secret = row.secret.clone();
                let original_encrypted = row.secret_encrypted.clone();
                let original_key_id = row.encryption_key_id.clone();
                let mut active: webhooks::ActiveModel = Default::default();
                if plan.clear_plaintext {
                    active.secret = Set(String::new());
                }
                active.secret_encrypted = Set(plan.encrypted);
                active.encryption_key_id = Set(Some(service.key_id().to_string()));
                let mut update = webhooks::Entity::update_many()
                    .set(active)
                    .filter(webhooks::Column::Id.eq(row.id.clone()))
                    .filter(webhooks::Column::Secret.eq(original_secret));
                update = match original_encrypted {
                    Some(value) => update.filter(webhooks::Column::SecretEncrypted.eq(value)),
                    None => update.filter(webhooks::Column::SecretEncrypted.is_null()),
                };
                update = match original_key_id {
                    Some(value) => update.filter(webhooks::Column::EncryptionKeyId.eq(value)),
                    None => update.filter(webhooks::Column::EncryptionKeyId.is_null()),
                };
                let result = update.exec(&transaction).await?;
                ensure_cas(result.rows_affected, "webhooks", row.id)?;
            }
            transaction.commit().await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use migration::MigratorTrait;
    use sea_orm::{
        ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DbBackend, Statement,
    };

    fn service() -> EncryptionService {
        EncryptionService::from_keyring_values(
            "active",
            &"11".repeat(32),
            Some(&format!("old={}", "22".repeat(32))),
        )
        .unwrap()
    }

    #[test]
    fn defaults_to_dry_run_and_rejects_unbounded_batches() {
        assert_eq!(RewrapOptions::parse(&[]).unwrap(), RewrapOptions::default());
        let error = RewrapOptions::parse(&["--batch-size".into(), "1001".into()]).unwrap_err();
        assert!(matches!(error, RewrapError::InvalidOption(_)));
        let conflict = RewrapOptions::parse(&["--apply".into(), "--dry-run".into()]);
        assert!(matches!(conflict, Err(RewrapError::InvalidOption(_))));
    }

    #[test]
    fn inventory_covers_ten_tables_and_fourteen_values() {
        assert_eq!(SECRET_INVENTORY.len(), 10);
        assert_eq!(
            SECRET_INVENTORY
                .iter()
                .map(|(_, fields)| fields.len())
                .sum::<usize>(),
            14
        );
    }

    #[test]
    fn plaintext_compatibility_is_migrated_and_conflicts_stop() {
        let service = service();
        let plan = plan_optional_secret(
            &service,
            Some("token"),
            None,
            "identities",
            "id",
            "access_token_encrypted",
        )
        .unwrap();
        assert!(plan.clear_plaintext);
        assert_eq!(
            service
                .decrypt_with_context(
                    plan.encrypted.as_deref().unwrap(),
                    EncryptionContext::new("identities", "id", "access_token_encrypted"),
                )
                .unwrap(),
            "token"
        );

        let encrypted = service.encrypt("different").unwrap();
        let error = plan_optional_secret(
            &service,
            Some("token"),
            Some(&encrypted),
            "identities",
            "id",
            "access_token_encrypted",
        )
        .unwrap_err();
        assert!(matches!(error, RewrapError::PlaintextConflict { .. }));
    }

    #[test]
    fn authenticated_empty_plaintext_is_not_a_valid_required_secret() {
        let service = service();
        for (table, field) in [
            ("organization_oauth_credentials", "client_secret_encrypted"),
            ("organization_billing_credentials", "api_key_encrypted"),
            ("user_totp_secrets", "secret_encrypted"),
            ("saml_signing_keys", "private_key_encrypted"),
            ("upstream_providers", "client_secret_encrypted"),
            ("webhooks", "secret_encrypted"),
        ] {
            let ciphertext = service
                .encrypt_with_context("", EncryptionContext::new(table, "record-a", field))
                .unwrap();
            assert!(matches!(
                plan_required_ciphertext(&service, &ciphertext, table, "record-a", field),
                Err(RewrapError::MissingRequiredSecret { .. })
            ));
        }
    }

    #[test]
    fn ambiguous_base64_text_is_never_guessed() {
        let error = plan_text_secret(&service(), "dG9rZW4=", "id", "api_key").unwrap_err();
        assert!(matches!(error, RewrapError::AmbiguousTextSecret { .. }));

        let mut tampered_envelope = service().encrypt("secret").unwrap();
        *tampered_envelope.last_mut().unwrap() ^= 1;
        let error = plan_text_secret(
            &service(),
            &BASE64.encode(tampered_envelope),
            "id",
            "api_key",
        )
        .unwrap_err();
        assert!(matches!(error, RewrapError::Ciphertext { .. }));
    }

    #[test]
    fn version_one_values_remain_readable_for_explicit_migration() {
        let service = service();
        let record_a = service.encrypt("secret-a").unwrap();
        let record_b = service.encrypt("secret-b").unwrap();

        // V1 has no record context, so migration must read it before producing
        // the context-bound V2 envelope.
        assert_eq!(service.decrypt(&record_b).unwrap(), "secret-b");
        assert_eq!(service.decrypt(&record_a).unwrap(), "secret-a");
    }

    #[test]
    fn version_two_values_cannot_be_swapped_between_records_or_fields() {
        let service = service();
        let context_a = EncryptionContext::new("siem_configs", "a", "api_key");
        let context_b = EncryptionContext::new("siem_configs", "b", "api_key");
        let wrong_field = EncryptionContext::new("siem_configs", "a", "auth_header");
        let encrypted = service.encrypt_with_context("secret-a", context_a).unwrap();

        assert_eq!(
            service.decrypt_with_context(&encrypted, context_a).unwrap(),
            "secret-a"
        );
        assert_eq!(
            service.decrypt_with_context(&encrypted, context_b),
            Err(EncryptionError::DecryptionFailed)
        );
        assert_eq!(
            service.decrypt_with_context(&encrypted, wrong_field),
            Err(EncryptionError::DecryptionFailed)
        );
    }

    #[test]
    fn oauth_compatibility_scanner_uses_exact_physical_encrypted_columns() {
        let service = service();
        for (table, record_id) in [
            ("identities", "identity-a"),
            ("connected_accounts", "account-a"),
        ] {
            let ciphertext = service
                .encrypt_with_context(
                    "token-canary",
                    EncryptionContext::new(table, record_id, "access_token_encrypted"),
                )
                .unwrap();
            let plan = plan_optional_secret(
                &service,
                None,
                Some(&ciphertext),
                table,
                record_id,
                "access_token_encrypted",
            )
            .unwrap();
            assert!(!plan.ciphertext_changed);

            let mut tampered = ciphertext.clone();
            *tampered.last_mut().unwrap() ^= 1;
            let damaged = plan_optional_secret(
                &service,
                None,
                Some(&tampered),
                table,
                record_id,
                "access_token_encrypted",
            );
            assert!(matches!(damaged, Err(RewrapError::Ciphertext { .. })));

            let wrong_field = plan_optional_secret(
                &service,
                None,
                Some(&ciphertext),
                table,
                record_id,
                "access_token",
            );
            assert!(matches!(wrong_field, Err(RewrapError::Ciphertext { .. })));

            let wrong_table = if table == "identities" {
                "connected_accounts"
            } else {
                "identities"
            };
            let swapped = plan_optional_secret(
                &service,
                None,
                Some(&ciphertext),
                wrong_table,
                record_id,
                "access_token_encrypted",
            );
            assert!(matches!(swapped, Err(RewrapError::Ciphertext { .. })));

            let plaintext = plan_optional_secret(
                &service,
                Some("plaintext-token-canary"),
                None,
                table,
                record_id,
                "refresh_token_encrypted",
            )
            .unwrap();
            assert!(plaintext.clear_plaintext);
            assert!(plaintext.plaintext_migrated);
            assert_eq!(
                service
                    .decrypt_with_context(
                        plaintext.encrypted.as_deref().unwrap(),
                        EncryptionContext::new(table, record_id, "refresh_token_encrypted"),
                    )
                    .unwrap(),
                "plaintext-token-canary"
            );
        }
    }

    #[test]
    fn cas_conflicts_are_explicit_and_never_treated_as_success() {
        assert!(ensure_cas(1, "table", "id".to_string()).is_ok());
        assert!(matches!(
            ensure_cas(0, "table", "id".to_string()),
            Err(RewrapError::ConcurrentModification { .. })
        ));
    }

    async fn database() -> DatabaseConnection {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.max_connections(1).min_connections(1);
        let database = Database::connect(options).await.unwrap();
        migration::Migrator::up(&database, None).await.unwrap();
        database
            .execute(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_keys = OFF".to_string(),
            ))
            .await
            .unwrap();
        database
    }

    async fn file_database(path: &std::path::Path, create: bool) -> DatabaseConnection {
        let mode = if create { "rwc" } else { "rw" };
        let mut options = ConnectOptions::new(format!("sqlite:{}?mode={mode}", path.display()));
        options.max_connections(1).min_connections(1);
        Database::connect(options).await.unwrap()
    }

    async fn insert_totp(database: &DatabaseConnection, id: &str, encrypted: Vec<u8>) {
        user_totp_secrets::ActiveModel {
            id: Set(id.to_string()),
            user_id: Set(format!("user-{id}")),
            secret_encrypted: Set(encrypted),
            encryption_key_id: Set("old".to_string()),
            enabled: Set(true),
            created_at: Set(Utc::now().naive_utc()),
            enabled_at: Set(None),
        }
        .insert(database)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn bounded_apply_resumes_and_finishes_idempotently() {
        let database = database().await;
        let old = EncryptionService::from_keyring_values("old", &"22".repeat(32), None).unwrap();
        insert_totp(&database, "a", old.encrypt("one").unwrap()).await;
        insert_totp(&database, "b", old.encrypt("two").unwrap()).await;
        let service = service();

        let dry = run(
            &database,
            &service,
            &RewrapOptions {
                batch_size: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(dry.complete);
        assert_eq!(dry.tables["user_totp_secrets"].rows_changed, 2);
        let still_old = user_totp_secrets::Entity::find_by_id("a")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still_old.encryption_key_id, "old");

        let partial = run(
            &database,
            &service,
            &RewrapOptions {
                apply: true,
                batch_size: 1,
                max_batches: Some(1),
            },
        )
        .await
        .unwrap();
        assert!(!partial.complete);
        let first = user_totp_secrets::Entity::find_by_id("a")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        let second = user_totp_secrets::Entity::find_by_id("b")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.encryption_key_id, "active");
        assert_eq!(second.encryption_key_id, "old");

        let completed = run(
            &database,
            &service,
            &RewrapOptions {
                apply: true,
                batch_size: 1,
                max_batches: Some(1),
            },
        )
        .await
        .unwrap();
        assert!(completed.complete);
        assert_eq!(completed.tables["user_totp_secrets"].rows_changed, 1);

        let verification = run(&database, &service, &RewrapOptions::default())
            .await
            .unwrap();
        assert!(verification.complete);
        assert_eq!(verification.tables["user_totp_secrets"].rows_changed, 0);
        for id in ["a", "b"] {
            let row = user_totp_secrets::Entity::find_by_id(id)
                .one(&database)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.encryption_key_id, "active");
            assert_eq!(
                service
                    .decrypt_with_context(
                        &row.secret_encrypted,
                        EncryptionContext::new("user_totp_secrets", &row.id, "secret_encrypted",),
                    )
                    .unwrap(),
                if id == "a" { "one" } else { "two" }
            );
        }
    }

    #[tokio::test]
    async fn runtime_readiness_is_page_bounded_and_time_bounded() {
        let database = database().await;
        let service = service();
        for index in 0..205 {
            let id = format!("page-{index:03}");
            let ciphertext = service
                .encrypt_with_context(
                    "bounded-page-canary",
                    EncryptionContext::new("user_totp_secrets", &id, "secret_encrypted"),
                )
                .unwrap();
            user_totp_secrets::ActiveModel {
                id: Set(id.clone()),
                user_id: Set(format!("user-{id}")),
                secret_encrypted: Set(ciphertext),
                encryption_key_id: Set(service.key_id().to_string()),
                enabled: Set(true),
                created_at: Set(Utc::now().naive_utc()),
                enabled_at: Set(None),
            }
            .insert(&database)
            .await
            .unwrap();
        }

        let report = verify_runtime_ready_with_timeout(
            &database,
            &service,
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(report.tables["user_totp_secrets"].rows_scanned, 205);
        assert_eq!(report.rows_requiring_changes(), 0);

        assert!(matches!(
            verify_runtime_ready_with_timeout(&database, &service, std::time::Duration::ZERO,)
                .await,
            Err(RewrapError::RuntimeReadinessTimeout { seconds: 0 })
        ));
    }

    #[tokio::test]
    async fn tamper_aborts_a_batch_without_partial_updates() {
        let database = database().await;
        let old = EncryptionService::from_keyring_values("old", &"22".repeat(32), None).unwrap();
        let first_ciphertext = old.encrypt("one").unwrap();
        let mut tampered = old.encrypt("two").unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        insert_totp(&database, "a", first_ciphertext.clone()).await;
        insert_totp(&database, "b", tampered).await;

        let result = run(
            &database,
            &service(),
            &RewrapOptions {
                apply: true,
                batch_size: 2,
                max_batches: None,
            },
        )
        .await;
        assert!(matches!(result, Err(RewrapError::Ciphertext { .. })));
        let first = user_totp_secrets::Entity::find_by_id("a")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.secret_encrypted, first_ciphertext);
        assert_eq!(first.encryption_key_id, "old");
    }

    #[tokio::test]
    async fn legacy_webhook_plaintext_is_explicitly_migrated_and_runtime_readable() {
        let database = database().await;
        let now = Utc::now().naive_utc();
        webhooks::ActiveModel {
            id: Set("webhook-a".to_string()),
            org_id: Set("org-a".to_string()),
            name: Set("Legacy".to_string()),
            url: Set("https://example.test/hook".to_string()),
            secret: Set("legacy-webhook-secret".to_string()),
            secret_encrypted: Set(None),
            encryption_key_id: Set(None),
            events: Set("[]".to_string()),
            is_active: Set(true),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&database)
        .await
        .unwrap();

        let service = service();
        let report = run(
            &database,
            &service,
            &RewrapOptions {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(report.tables["webhooks"].plaintext_values_migrated, 1);

        let row = webhooks::Entity::find_by_id("webhook-a")
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert!(row.secret.is_empty());
        assert_eq!(row.encryption_key_id.as_deref(), Some("active"));
        assert_eq!(
            service
                .decrypt_with_context(
                    row.secret_encrypted.as_deref().unwrap(),
                    EncryptionContext::new("webhooks", &row.id, "secret_encrypted"),
                )
                .unwrap(),
            "legacy-webhook-secret"
        );
    }

    #[tokio::test]
    async fn webhook_without_plaintext_or_ciphertext_fails_readiness_without_secret_output() {
        let database = database().await;
        let now = Utc::now().naive_utc();
        let record_id = "missing-webhook-secret";
        webhooks::ActiveModel {
            id: Set(record_id.to_string()),
            org_id: Set("org-a".to_string()),
            name: Set("Invalid".to_string()),
            url: Set("https://example.test/hook".to_string()),
            secret: Set(String::new()),
            secret_encrypted: Set(None),
            encryption_key_id: Set(None),
            events: Set("[]".to_string()),
            is_active: Set(false),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&database)
        .await
        .unwrap();

        let error = verify_runtime_ready(&database, &service())
            .await
            .expect_err("missing webhook signing material must fail readiness");
        let message = error.to_string();
        assert!(matches!(error, RewrapError::MissingRequiredSecret { .. }));
        assert!(message.contains(record_id));
        assert!(!message.contains("webhook-secret-canary"));
    }

    #[tokio::test]
    async fn only_saml_upstream_rows_may_use_the_empty_secret_sentinel() {
        let database = database().await;
        let now = Utc::now().naive_utc();
        for (id, provider_type) in [("saml-empty", "saml"), ("oidc-empty", "oidc")] {
            upstream_providers::ActiveModel {
                id: Set(id.to_string()),
                org_id: Set("org-a".to_string()),
                connection_id: Set(format!("connection-{id}")),
                name: Set(id.to_string()),
                provider_type: Set(provider_type.to_string()),
                client_id: Set(format!("client-{id}")),
                client_secret_encrypted: Set(Vec::new()),
                encryption_key_id: Set(service().key_id().to_string()),
                authorization_url: Set(Some("https://example.test/login".to_string())),
                token_url: Set(None),
                userinfo_url: Set(None),
                discovery_url: Set(None),
                scopes: Set(None),
                issuer: Set(None),
                metadata: Set(None),
                enabled: Set(false),
                created_at: Set(now),
                updated_at: Set(now),
            }
            .insert(&database)
            .await
            .unwrap();
        }

        let error = verify_runtime_ready(&database, &service())
            .await
            .expect_err("OAuth/OIDC empty secret sentinel must fail readiness");
        assert!(matches!(
            error,
            RewrapError::MissingRequiredSecret {
                table: "upstream_providers",
                record_id,
                field: "client_secret_encrypted",
            } if record_id == "oidc-empty"
        ));
    }

    #[tokio::test]
    async fn restored_oauth_tokens_require_old_key_until_rewrapped_and_are_secret_free_in_reports()
    {
        let root =
            std::env::temp_dir().join(format!("authos-secret-restore-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let source_path = root.join("source.db");
        let backup_path = root.join("backup.db");
        let restored_path = root.join("restored.db");

        let source = file_database(&source_path, true).await;
        migration::Migrator::up(&source, None).await.unwrap();
        source
            .execute(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_keys = OFF".to_string(),
            ))
            .await
            .unwrap();

        let old = EncryptionService::from_keyring_values("old", &"22".repeat(32), None).unwrap();
        let now = Utc::now().naive_utc();
        let identity_access = "identity-access-secret-canary";
        let identity_refresh = "identity-refresh-secret-canary";
        let account_access = "account-access-secret-canary";
        let account_refresh = "account-refresh-secret-canary";
        let identity_id = "restore-identity";
        let account_id = "restore-account";

        identities::ActiveModel {
            id: Set(identity_id.to_string()),
            user_id: Set("restore-user".to_string()),
            provider: Set("google".to_string()),
            provider_user_id: Set("restore-provider-identity".to_string()),
            access_token: Set(None),
            refresh_token: Set(None),
            access_token_encrypted: Set(Some(
                old.encrypt_with_context(
                    identity_access,
                    EncryptionContext::new("identities", identity_id, "access_token_encrypted"),
                )
                .unwrap(),
            )),
            refresh_token_encrypted: Set(Some(
                old.encrypt_with_context(
                    identity_refresh,
                    EncryptionContext::new("identities", identity_id, "refresh_token_encrypted"),
                )
                .unwrap(),
            )),
            encryption_key_id: Set(Some("old".to_string())),
            expires_at: Set(None),
            scopes: Set(Some("[]".to_string())),
            last_refreshed_at: Set(None),
            issuing_org_id: Set(None),
            issuing_service_id: Set(None),
            created_at: Set(now),
        }
        .insert(&source)
        .await
        .unwrap();

        connected_accounts::ActiveModel {
            id: Set(account_id.to_string()),
            user_id: Set("restore-user".to_string()),
            provider: Set("github".to_string()),
            provider_user_id: Set("restore-provider-account".to_string()),
            email: Set(None),
            display_name: Set(None),
            access_token: Set(None),
            refresh_token: Set(None),
            access_token_encrypted: Set(Some(
                old.encrypt_with_context(
                    account_access,
                    EncryptionContext::new(
                        "connected_accounts",
                        account_id,
                        "access_token_encrypted",
                    ),
                )
                .unwrap(),
            )),
            refresh_token_encrypted: Set(Some(
                old.encrypt_with_context(
                    account_refresh,
                    EncryptionContext::new(
                        "connected_accounts",
                        account_id,
                        "refresh_token_encrypted",
                    ),
                )
                .unwrap(),
            )),
            encryption_key_id: Set(Some("old".to_string())),
            expires_at: Set(None),
            scopes: Set(Some("[]".to_string())),
            last_refreshed_at: Set(None),
            status: Set("active".to_string()),
            linked_at: Set(now),
            updated_at: Set(now),
            revoked_at: Set(None),
        }
        .insert(&source)
        .await
        .unwrap();
        source.close().await.unwrap();

        std::fs::copy(&source_path, &backup_path).unwrap();
        std::fs::copy(&backup_path, &restored_path).unwrap();
        let restored = file_database(&restored_path, false).await;
        let rotating = service();
        let readiness = verify_runtime_ready(&restored, &rotating).await;
        let readiness_message = readiness.as_ref().unwrap_err().to_string();
        for canary in [
            identity_access,
            identity_refresh,
            account_access,
            account_refresh,
        ] {
            assert!(!readiness_message.contains(canary));
        }
        assert!(matches!(
            readiness,
            Err(RewrapError::RuntimeRequiresRewrap {
                rows_changed: 2,
                secrets_requiring_rewrap: 4,
                plaintext_values_requiring_migration: 0,
            })
        ));

        let report = run(
            &restored,
            &rotating,
            &RewrapOptions {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let serialized = serde_json::to_string(&report).unwrap();
        for canary in [
            identity_access,
            identity_refresh,
            account_access,
            account_refresh,
        ] {
            assert!(!serialized.contains(canary));
        }
        verify_runtime_ready(&restored, &rotating).await.unwrap();

        let retired =
            EncryptionService::from_keyring_values("active", &"11".repeat(32), None).unwrap();
        let identity = identities::Entity::find_by_id(identity_id)
            .one(&restored)
            .await
            .unwrap()
            .unwrap();
        let account = connected_accounts::Entity::find_by_id(account_id)
            .one(&restored)
            .await
            .unwrap()
            .unwrap();
        assert!(identity.access_token.is_none() && identity.refresh_token.is_none());
        assert!(account.access_token.is_none() && account.refresh_token.is_none());
        for (ciphertext, table, id, field, expected) in [
            (
                identity.access_token_encrypted.as_deref().unwrap(),
                "identities",
                identity_id,
                "access_token_encrypted",
                identity_access,
            ),
            (
                identity.refresh_token_encrypted.as_deref().unwrap(),
                "identities",
                identity_id,
                "refresh_token_encrypted",
                identity_refresh,
            ),
            (
                account.access_token_encrypted.as_deref().unwrap(),
                "connected_accounts",
                account_id,
                "access_token_encrypted",
                account_access,
            ),
            (
                account.refresh_token_encrypted.as_deref().unwrap(),
                "connected_accounts",
                account_id,
                "refresh_token_encrypted",
                account_refresh,
            ),
        ] {
            assert_eq!(
                retired
                    .decrypt_with_context(ciphertext, EncryptionContext::new(table, id, field))
                    .unwrap(),
                expected
            );
        }
        restored.close().await.unwrap();

        // A retained backup still referencing the old key must make retirement
        // fail closed; the previous key remains required for that backup.
        let backup = file_database(&backup_path, false).await;
        let backup_readiness = verify_runtime_ready(&backup, &retired).await;
        let backup_message = backup_readiness.as_ref().unwrap_err().to_string();
        for canary in [
            identity_access,
            identity_refresh,
            account_access,
            account_refresh,
        ] {
            assert!(!backup_message.contains(canary));
        }
        assert!(matches!(
            backup_readiness,
            Err(RewrapError::Ciphertext {
                source: EncryptionError::UnknownKey,
                ..
            })
        ));
        backup.close().await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}

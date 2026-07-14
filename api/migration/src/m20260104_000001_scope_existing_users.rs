use sea_orm::Statement;
use sea_orm_migration::prelude::*;
use std::collections::{HashMap, HashSet};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Debug, Clone)]
struct UserRow {
    id: String,
    #[allow(dead_code)]
    email: String,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        // 1. Get all users who are NOT platform owners and have NULL org_id
        let user_rows = db
            .query_all(Statement::from_string(
                backend,
                "SELECT id, email FROM users WHERE org_id IS NULL AND is_platform_owner = FALSE"
                    .to_owned(),
            ))
            .await?;

        let mut users = Vec::new();
        for row in user_rows {
            let id: String = row.try_get("", "id")?;
            let email: String = row.try_get("", "email")?;
            users.push(UserRow { id, email });
        }

        // 2. Get all identities with service_id (to link to org)
        // We check both issuing_org_id (direct link) and issuing_service_id (via service)
        let identity_rows = db
            .query_all(Statement::from_string(
                backend,
                [
                    "SELECT i.user_id, s.org_id",
                    "FROM identities i",
                    "JOIN services s ON i.issuing_service_id = s.id",
                    "WHERE i.issuing_service_id IS NOT NULL",
                    "UNION",
                    "SELECT user_id, issuing_org_id as org_id",
                    "FROM identities",
                    "WHERE issuing_org_id IS NOT NULL",
                ]
                .join(" "),
            ))
            .await?;

        // Map user_id -> Set of org_ids
        let mut user_orgs: HashMap<String, HashSet<String>> = HashMap::new();

        for row in identity_rows {
            let user_id: String = row.try_get("", "user_id")?;
            let org_id: String = row.try_get("", "org_id")?;

            user_orgs.entry(user_id).or_default().insert(org_id);
        }

        // 3. Process users
        for user in users {
            if let Some(org_ids) = user_orgs.get(&user.id) {
                let orgs: Vec<&String> = org_ids.iter().collect();

                if orgs.is_empty() {
                    continue;
                }

                if orgs.len() == 1 {
                    // Case A: User belongs to exactly one Org -> Update user record
                    let org_id = orgs[0];
                    db.execute(Statement::from_sql_and_values(
                        backend,
                        "UPDATE users SET org_id = ? WHERE id = ?",
                        vec![org_id.into(), user.id.into()], // Pass primitives, SeaORM handles wrapping
                    ))
                    .await?;
                } else {
                    // Case B: User belongs to multiple Orgs -> Split
                    // 1. Update original user to belong to first org
                    let first_org_id = orgs[0];
                    db.execute(Statement::from_sql_and_values(
                        backend,
                        "UPDATE users SET org_id = ? WHERE id = ?",
                        vec![first_org_id.into(), user.id.clone().into()],
                    ))
                    .await?;

                    // 2. Create new users for subsequent orgs
                    for &other_org_id in orgs.iter().skip(1) {
                        let new_user_id = uuid::Uuid::new_v4().to_string();

                        // Copy user data to new user row
                        db.execute(Statement::from_sql_and_values(
                            backend,
                            "INSERT INTO users (id, email, org_id, is_platform_owner, password_hash, email_verified_at, created_at, updated_at, deleted_at)
                             SELECT ?, email, ?, is_platform_owner, password_hash, email_verified_at, created_at, updated_at, deleted_at 
                             FROM users WHERE id = ?",
                             vec![new_user_id.clone().into(), other_org_id.into(), user.id.clone().into()]
                        )).await?;

                        // Move relevant identities to new user based on service or org
                        let update_sql = "UPDATE identities SET user_id = ? WHERE user_id = ? AND (issuing_org_id = ? OR issuing_service_id IN (SELECT id FROM services WHERE org_id = ?))".to_string();

                        db.execute(Statement::from_sql_and_values(
                            backend,
                            &update_sql,
                            vec![
                                new_user_id.into(),
                                user.id.clone().into(),
                                other_org_id.into(),
                                other_org_id.into(),
                            ],
                        ))
                        .await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Reverting this is destructive and complex (merging split users).
        // For now, we will just set org_id back to NULL for all users that were not platform owners?
        // But we can't easily distinguishing them from newly created scoped users.
        // Downgrade is "best effort": Update all users to NULL org_id?
        // No, that destroys the scoping we just added.
        // Let's leave down() empty or minimal, as reverting semantic data changes is ambiguous.
        // Or strictly: UPDATE users SET org_id = NULL.
        // But then we have duplicate emails (from the split).
        // So we can't revert without violating uniqueness constraint on (email) if we drop org_id.

        // Since m20260103 adds the column, reverting THIS migration (m20260104) implies we still have the column but revert the DATA changes.
        // We cannot merge split users automatically.
        // We will just return Ok(()), effectively making this a one-way data migration.
        Ok(())
    }
}

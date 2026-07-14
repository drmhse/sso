use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_column("sessions", "refresh_token_hash").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Sessions::Table)
                        .add_column(
                            ColumnDef::new(Sessions::RefreshTokenHash)
                                .string_len(64)
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        if !manager
            .has_index("sessions", "idx_sessions_refresh_token_hash")
            .await?
        {
            manager
                .create_index(
                    Index::create()
                        .name("idx_sessions_refresh_token_hash")
                        .table(Sessions::Table)
                        .col(Sessions::RefreshTokenHash)
                        .unique()
                        .to_owned(),
                )
                .await?;
        }

        manager
            .create_table(
                Table::create()
                    .table(SessionRefreshTokenHistory::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SessionRefreshTokenHistory::TokenHash)
                            .string_len(64)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SessionRefreshTokenHistory::SessionId)
                            // Match the original `sessions.id` VARCHAR width so
                            // MySQL can create the foreign key.
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SessionRefreshTokenHistory::ConsumedAt)
                            .date_time()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_session_refresh_history_session")
                            .from(
                                SessionRefreshTokenHistory::Table,
                                SessionRefreshTokenHistory::SessionId,
                            )
                            .to(Sessions::Table, Sessions::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        if !manager
            .has_index(
                "session_refresh_token_history",
                "idx_session_refresh_history_session",
            )
            .await?
        {
            manager
                .create_index(
                    Index::create()
                        .name("idx_session_refresh_history_session")
                        .table(SessionRefreshTokenHistory::Table)
                        .col(SessionRefreshTokenHistory::SessionId)
                        .to_owned(),
                )
                .await?;
        }

        // Existing plaintext refresh tokens cannot be portably hashed inside a
        // three-database schema migration without exposing them to application
        // logs or backend-specific SQL. Invalidate them instead: access tokens
        // keep their existing lifetime, but refresh requires reauthentication.
        let clear_plaintext = Query::update()
            .table(Sessions::Table)
            .value(Sessions::RefreshToken, Expr::value(Option::<String>::None))
            .to_owned();
        manager
            .get_connection()
            .execute(manager.get_database_backend().build(&clear_plaintext))
            .await?;

        if manager
            .has_index("sessions", "idx_sessions_refresh_token")
            .await?
        {
            manager
                .drop_index(
                    Index::drop()
                        .name("idx_sessions_refresh_token")
                        .table(Sessions::Table)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(SessionRefreshTokenHistory::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        if manager
            .has_index("sessions", "idx_sessions_refresh_token_hash")
            .await?
        {
            manager
                .drop_index(
                    Index::drop()
                        .name("idx_sessions_refresh_token_hash")
                        .table(Sessions::Table)
                        .to_owned(),
                )
                .await?;
        }
        if manager.has_column("sessions", "refresh_token_hash").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Sessions::Table)
                        .drop_column(Sessions::RefreshTokenHash)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Sessions {
    Table,
    Id,
    RefreshToken,
    RefreshTokenHash,
}

#[derive(DeriveIden)]
enum SessionRefreshTokenHistory {
    Table,
    TokenHash,
    SessionId,
    ConsumedAt,
}

#[cfg(all(test, feature = "db_sqlite"))]
mod tests {
    use super::*;
    use sea_orm_migration::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};

    #[tokio::test]
    async fn upgrade_clears_legacy_refresh_bearers_instead_of_copying_them() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        let manager = SchemaManager::new(&db);
        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .col(
                        ColumnDef::new(Sessions::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Sessions::RefreshToken).string().null())
                    .to_owned(),
            )
            .await
            .expect("create legacy sessions table");
        manager
            .create_index(
                Index::create()
                    .name("idx_sessions_refresh_token")
                    .table(Sessions::Table)
                    .col(Sessions::RefreshToken)
                    .to_owned(),
            )
            .await
            .expect("create legacy refresh index");
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "INSERT INTO sessions (id, refresh_token) VALUES ('session-1', 'legacy-bearer')",
        ))
        .await
        .expect("insert legacy session");

        Migration
            .up(&manager)
            .await
            .expect("run hardening migration");

        let row = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT refresh_token, refresh_token_hash FROM sessions WHERE id = 'session-1'",
            ))
            .await
            .expect("query migrated session")
            .expect("migrated session exists");
        assert_eq!(
            row.try_get::<Option<String>>("", "refresh_token")
                .expect("read legacy column"),
            None
        );
        assert_eq!(
            row.try_get::<Option<String>>("", "refresh_token_hash")
                .expect("read hash column"),
            None
        );
        assert!(manager
            .has_table("session_refresh_token_history")
            .await
            .expect("inspect history table"));
    }
}

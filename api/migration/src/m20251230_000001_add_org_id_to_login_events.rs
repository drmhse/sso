use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DbBackend;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Sqlite {
            // SQLite does not support adding foreign keys to existing tables, so we must rewrite the table
            let db = manager.get_connection();

            // A crash/restart during this table-rewrite migration can leave the old
            // table renamed before SeaORM records the migration. Finish the rewrite
            // before treating the new column as a completed migration.
            if self.table_exists(db, "login_events_old").await? {
                if !self.table_exists(db, "login_events").await? {
                    self.create_sqlite_login_events_with_org(manager).await?;
                } else if !self.column_exists(db, "login_events", "org_id").await? {
                    return Err(DbErr::Migration(
                        "login_events_old exists but login_events is not the rewritten table"
                            .to_string(),
                    ));
                }

                self.copy_sqlite_login_events_from_old(db).await?;
                self.drop_sqlite_old_login_events(manager).await?;
                self.ensure_sqlite_indexes(db).await?;
                return Ok(());
            }

            // A crash/restart after the table was fully rewritten, but before SeaORM
            // recorded the migration, can leave the new column already in place.
            if self.column_exists(db, "login_events", "org_id").await? {
                self.ensure_sqlite_indexes(db).await?;
                return Ok(());
            }

            // 1. Drop existing index (it stays when table is renamed)
            db.execute_unprepared("DROP INDEX IF EXISTS idx_login_events_created")
                .await?;

            // 2. Rename existing table
            manager
                .rename_table(
                    Table::rename()
                        .table(LoginEvents::Table, Alias::new("login_events_old"))
                        .to_owned(),
                )
                .await?;

            // 2. Create new table with the new column and foreign key
            self.create_sqlite_login_events_with_org(manager).await?;

            // 3. Copy data from old table to new table
            self.copy_sqlite_login_events_from_old(db).await?;

            // 4. Drop old table
            self.drop_sqlite_old_login_events(manager).await?;

            // 5. Restore indexes
            self.ensure_sqlite_indexes(db).await?;
        } else {
            // Standard approach for Postgres/MySQL
            manager
                .alter_table(
                    Table::alter()
                        .table(LoginEvents::Table)
                        .add_column(ColumnDef::new(LoginEvents::OrgId).string_len(36).null())
                        .to_owned(),
                )
                .await?;

            manager
                .create_index(
                    Index::create()
                        .if_not_exists()
                        .name("idx_login_events_org")
                        .table(LoginEvents::Table)
                        .col(LoginEvents::OrgId)
                        .to_owned(),
                )
                .await?;

            manager
                .create_foreign_key(
                    ForeignKey::create()
                        .name("fk_login_events_org")
                        .from(LoginEvents::Table, LoginEvents::OrgId)
                        .to(Organizations::Table, Organizations::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Sqlite {
            // Rewrite without the org_id column
            manager
                .rename_table(
                    Table::rename()
                        .table(LoginEvents::Table, Alias::new("login_events_old"))
                        .to_owned(),
                )
                .await?;

            manager
                .create_table(
                    Table::create()
                        .table(LoginEvents::Table)
                        .col(
                            ColumnDef::new(LoginEvents::Id)
                                .string()
                                .not_null()
                                .primary_key(),
                        )
                        .col(
                            ColumnDef::new(LoginEvents::UserId)
                                .string_len(36)
                                .not_null(),
                        )
                        .col(ColumnDef::new(LoginEvents::ServiceId).string_len(36).null())
                        .col(
                            ColumnDef::new(LoginEvents::Provider)
                                .string_len(100)
                                .not_null(),
                        )
                        .col(ColumnDef::new(LoginEvents::IpAddress).string_len(50).null())
                        .col(ColumnDef::new(LoginEvents::UserAgent).string().null())
                        .col(
                            ColumnDef::new(LoginEvents::CreatedAt)
                                .date_time()
                                .not_null()
                                .default(Expr::current_timestamp()),
                        )
                        .col(ColumnDef::new(LoginEvents::RiskScore).integer().null())
                        .col(ColumnDef::new(LoginEvents::RiskFactors).string().null())
                        .col(ColumnDef::new(LoginEvents::GeoCountry).string().null())
                        .col(ColumnDef::new(LoginEvents::GeoCity).string().null())
                        .col(ColumnDef::new(LoginEvents::GeoLat).double().null())
                        .col(ColumnDef::new(LoginEvents::GeoLong).double().null())
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_login_events_user")
                                .from(LoginEvents::Table, LoginEvents::UserId)
                                .to(Users::Table, Users::Id)
                                .on_delete(ForeignKeyAction::Cascade),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk_login_events_service")
                                .from(LoginEvents::Table, LoginEvents::ServiceId)
                                .to(Services::Table, Services::Id)
                                .on_delete(ForeignKeyAction::Cascade),
                        )
                        .to_owned(),
                )
                .await?;

            let db = manager.get_connection();
            db.execute_unprepared(
                "INSERT INTO login_events (id, user_id, service_id, provider, ip_address, user_agent, created_at, risk_score, risk_factors, geo_country, geo_city, geo_lat, geo_long) \
                 SELECT id, user_id, service_id, provider, ip_address, user_agent, created_at, risk_score, risk_factors, geo_country, geo_city, geo_lat, geo_long FROM login_events_old"
            ).await?;

            manager
                .drop_table(
                    Table::drop()
                        .table(Alias::new("login_events_old"))
                        .to_owned(),
                )
                .await?;

            manager
                .create_index(
                    Index::create()
                        .name("idx_login_events_created")
                        .table(LoginEvents::Table)
                        .col(LoginEvents::CreatedAt)
                        .to_owned(),
                )
                .await?;
        } else {
            manager
                .drop_foreign_key(
                    ForeignKey::drop()
                        .name("fk_login_events_org")
                        .table(LoginEvents::Table)
                        .to_owned(),
                )
                .await?;

            manager
                .drop_index(
                    Index::drop()
                        .if_exists()
                        .name("idx_login_events_org")
                        .table(LoginEvents::Table)
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(LoginEvents::Table)
                        .drop_column(LoginEvents::OrgId)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

impl Migration {
    async fn table_exists<'a>(
        &self,
        db: &SchemaManagerConnection<'a>,
        table_name: &str,
    ) -> Result<bool, DbErr> {
        let result = db
            .query_one(sea_orm_migration::sea_orm::Statement::from_string(
                DbBackend::Sqlite,
                format!(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='{}'",
                    table_name
                ),
            ))
            .await?;
        Ok(result.is_some())
    }

    async fn column_exists<'a>(
        &self,
        db: &SchemaManagerConnection<'a>,
        table_name: &str,
        column_name: &str,
    ) -> Result<bool, DbErr> {
        let rows = db
            .query_all(sea_orm_migration::sea_orm::Statement::from_string(
                DbBackend::Sqlite,
                format!("PRAGMA table_info({})", table_name),
            ))
            .await?;

        for row in rows {
            if let Ok(name) = row.try_get::<String>("", "name") {
                if name == column_name {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn create_sqlite_login_events_with_org<'a>(
        &self,
        manager: &SchemaManager<'a>,
    ) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(LoginEvents::Table)
                    .col(
                        ColumnDef::new(LoginEvents::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(LoginEvents::UserId)
                            .string_len(36)
                            .not_null(),
                    )
                    .col(ColumnDef::new(LoginEvents::ServiceId).string_len(36).null())
                    .col(ColumnDef::new(LoginEvents::OrgId).string_len(36).null())
                    .col(
                        ColumnDef::new(LoginEvents::Provider)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(ColumnDef::new(LoginEvents::IpAddress).string_len(50).null())
                    .col(ColumnDef::new(LoginEvents::UserAgent).string().null())
                    .col(
                        ColumnDef::new(LoginEvents::CreatedAt)
                            .date_time()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(ColumnDef::new(LoginEvents::RiskScore).integer().null())
                    .col(ColumnDef::new(LoginEvents::RiskFactors).string().null())
                    .col(ColumnDef::new(LoginEvents::GeoCountry).string().null())
                    .col(ColumnDef::new(LoginEvents::GeoCity).string().null())
                    .col(ColumnDef::new(LoginEvents::GeoLat).double().null())
                    .col(ColumnDef::new(LoginEvents::GeoLong).double().null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_events_user")
                            .from(LoginEvents::Table, LoginEvents::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_events_service")
                            .from(LoginEvents::Table, LoginEvents::ServiceId)
                            .to(Services::Table, Services::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_events_org")
                            .from(LoginEvents::Table, LoginEvents::OrgId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn copy_sqlite_login_events_from_old<'a>(
        &self,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        db.execute_unprepared(
            "INSERT OR IGNORE INTO login_events (id, user_id, service_id, provider, ip_address, user_agent, created_at, risk_score, risk_factors, geo_country, geo_city, geo_lat, geo_long) \
             SELECT id, user_id, service_id, provider, ip_address, user_agent, created_at, risk_score, risk_factors, geo_country, geo_city, geo_lat, geo_long FROM login_events_old",
        )
        .await?;
        Ok(())
    }

    async fn drop_sqlite_old_login_events<'a>(
        &self,
        manager: &SchemaManager<'a>,
    ) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("login_events_old"))
                    .to_owned(),
            )
            .await
    }

    async fn ensure_sqlite_indexes<'a>(
        &self,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        db.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_login_events_created ON login_events (created_at)",
        )
        .await?;
        db.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_login_events_org ON login_events (org_id)",
        )
        .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum LoginEvents {
    Table,
    Id,
    UserId,
    ServiceId,
    OrgId,
    Provider,
    IpAddress,
    UserAgent,
    CreatedAt,
    RiskScore,
    RiskFactors,
    GeoCountry,
    GeoCity,
    GeoLat,
    GeoLong,
}

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Services {
    Table,
    Id,
}

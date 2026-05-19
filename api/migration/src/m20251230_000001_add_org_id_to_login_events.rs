use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DbBackend;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Sqlite {
            // SQLite does not support adding foreign keys to existing tables, so we must rewrite the table
            
            // 1. Drop existing index (it stays when table is renamed)
            manager.drop_index(
                Index::drop()
                    .name("idx_login_events_created")
                    .table(LoginEvents::Table)
                    .to_owned()
            ).await?;

            // 2. Rename existing table
            manager.rename_table(
                Table::rename().table(LoginEvents::Table, Alias::new("login_events_old")).to_owned()
            ).await?;

            // 2. Create new table with the new column and foreign key
            manager.create_table(
                Table::create()
                    .table(LoginEvents::Table)
                    .col(ColumnDef::new(LoginEvents::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(LoginEvents::UserId).string_len(36).not_null())
                    .col(ColumnDef::new(LoginEvents::ServiceId).string_len(36).null())
                    .col(ColumnDef::new(LoginEvents::OrgId).string_len(36).null()) // NEW COLUMN
                    .col(ColumnDef::new(LoginEvents::Provider).string_len(100).not_null())
                    .col(ColumnDef::new(LoginEvents::IpAddress).string_len(50).null())
                    .col(ColumnDef::new(LoginEvents::UserAgent).string().null())
                    .col(ColumnDef::new(LoginEvents::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
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
                            .on_delete(ForeignKeyAction::Cascade)
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_events_service")
                            .from(LoginEvents::Table, LoginEvents::ServiceId)
                            .to(Services::Table, Services::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_events_org")
                            .from(LoginEvents::Table, LoginEvents::OrgId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                    )
                    .to_owned()
            ).await?;

            // 3. Copy data from old table to new table
            let db = manager.get_connection();
            db.execute_unprepared(
                "INSERT INTO login_events (id, user_id, service_id, provider, ip_address, user_agent, created_at, risk_score, risk_factors, geo_country, geo_city, geo_lat, geo_long) \
                 SELECT id, user_id, service_id, provider, ip_address, user_agent, created_at, risk_score, risk_factors, geo_country, geo_city, geo_lat, geo_long FROM login_events_old"
            ).await?;

            // 4. Drop old table
            manager.drop_table(
                Table::drop().table(Alias::new("login_events_old")).to_owned()
            ).await?;

            // 5. Restore indexes
            manager.create_index(
                Index::create()
                    .name("idx_login_events_created")
                    .table(LoginEvents::Table)
                    .col(LoginEvents::CreatedAt)
                    .to_owned()
            ).await?;
            
            manager.create_index(
                Index::create()
                    .name("idx_login_events_org")
                    .table(LoginEvents::Table)
                    .col(LoginEvents::OrgId)
                    .to_owned()
            ).await?;

        } else {
            // Standard approach for Postgres/MySQL
            manager.alter_table(
                Table::alter()
                    .table(LoginEvents::Table)
                    .add_column(ColumnDef::new(LoginEvents::OrgId).string_len(36).null())
                    .to_owned(),
            ).await?;

            manager.create_index(
                Index::create()
                    .name("idx_login_events_org")
                    .table(LoginEvents::Table)
                    .col(LoginEvents::OrgId)
                    .to_owned()
            ).await?;

            manager.create_foreign_key(
                ForeignKey::create()
                    .name("fk_login_events_org")
                    .from(LoginEvents::Table, LoginEvents::OrgId)
                    .to(Organizations::Table, Organizations::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned()
            ).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Sqlite {
            // Rewrite without the org_id column
            manager.rename_table(
                Table::rename().table(LoginEvents::Table, Alias::new("login_events_old")).to_owned()
            ).await?;

            manager.create_table(
                Table::create()
                    .table(LoginEvents::Table)
                    .col(ColumnDef::new(LoginEvents::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(LoginEvents::UserId).string_len(36).not_null())
                    .col(ColumnDef::new(LoginEvents::ServiceId).string_len(36).null())
                    .col(ColumnDef::new(LoginEvents::Provider).string_len(100).not_null())
                    .col(ColumnDef::new(LoginEvents::IpAddress).string_len(50).null())
                    .col(ColumnDef::new(LoginEvents::UserAgent).string().null())
                    .col(ColumnDef::new(LoginEvents::CreatedAt).date_time().not_null().default(Expr::current_timestamp()))
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
                            .on_delete(ForeignKeyAction::Cascade)
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_login_events_service")
                            .from(LoginEvents::Table, LoginEvents::ServiceId)
                            .to(Services::Table, Services::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                    )
                    .to_owned()
            ).await?;

            let db = manager.get_connection();
            db.execute_unprepared(
                "INSERT INTO login_events (id, user_id, service_id, provider, ip_address, user_agent, created_at, risk_score, risk_factors, geo_country, geo_city, geo_lat, geo_long) \
                 SELECT id, user_id, service_id, provider, ip_address, user_agent, created_at, risk_score, risk_factors, geo_country, geo_city, geo_lat, geo_long FROM login_events_old"
            ).await?;

            manager.drop_table(
                Table::drop().table(Alias::new("login_events_old")).to_owned()
            ).await?;

            manager.create_index(
                Index::create()
                    .name("idx_login_events_created")
                    .table(LoginEvents::Table)
                    .col(LoginEvents::CreatedAt)
                    .to_owned()
            ).await?;
        } else {
            manager.drop_foreign_key(
                ForeignKey::drop()
                    .name("fk_login_events_org")
                    .table(LoginEvents::Table)
                    .to_owned()
            ).await?;

            manager.drop_index(
                Index::drop()
                    .name("idx_login_events_org")
                    .table(LoginEvents::Table)
                    .to_owned()
            ).await?;

            manager.alter_table(
                Table::alter()
                    .table(LoginEvents::Table)
                    .drop_column(LoginEvents::OrgId)
                    .to_owned(),
            ).await?;
        }

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

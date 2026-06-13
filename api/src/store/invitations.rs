use crate::constants::DEFAULT_MAX_USERS;
use crate::entities::permissions::RelationTuple;
use crate::entities::prelude::{OrganizationInvitations, Organizations};
use crate::entities::{organization_invitations, organizations};
use crate::error::Result;
use crate::store::{
    memberships::MembershipStore, organization_tiers::OrganizationTierStore,
    permissions::PermissionsStore, DB,
};
use chrono::NaiveDateTime;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter,
    QuerySelect, Set,
};
/// Invitation with organization details
#[derive(Debug, FromQueryResult)]
pub struct InvitationWithOrg {
    pub id: String,
    pub email: String,
    pub role: String,
    pub token: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub org_slug: String,
    pub org_name: String,
}

/// Invitation with inviter details
#[derive(Debug, FromQueryResult)]
pub struct InvitationWithInviter {
    pub id: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub token: String,
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub inviter_email: String,
    pub inviter_id: String,
    pub inviter_created_at: NaiveDateTime,
}

pub struct InvitationStore;

impl InvitationStore {
    /// Count pending invitations by org and email
    pub async fn count_pending_by_org_and_email(
        db: DB<'_>,
        org_id: &str,
        email: &str,
    ) -> Result<i64> {
        let count = OrganizationInvitations::find()
            .filter(organization_invitations::Column::OrgId.eq(org_id))
            .filter(organization_invitations::Column::Email.eq(email))
            .filter(organization_invitations::Column::Status.eq("pending"))
            .count(&db)
            .await?;

        Ok(count as i64)
    }

    /// List user's pending invitations with organization details
    pub async fn list_user_pending_invitations(
        db: DB<'_>,
        email: &str,
    ) -> Result<Vec<InvitationWithOrg>> {
        use crate::entities::prelude::OrganizationInvitations;
        use sea_orm::{JoinType, QueryOrder, RelationTrait};

        let invitations = match db {
            DB::Conn(conn) => {
                OrganizationInvitations::find()
                    .join(
                        JoinType::InnerJoin,
                        crate::entities::organization_invitations::Relation::Organizations.def(),
                    )
                    .select_only()
                    .column_as(organization_invitations::Column::Id, "id")
                    .column_as(organization_invitations::Column::Email, "email")
                    .column_as(organization_invitations::Column::Role, "role")
                    .column_as(organization_invitations::Column::Token, "token")
                    .column_as(organization_invitations::Column::ExpiresAt, "expires_at")
                    .column_as(organization_invitations::Column::CreatedAt, "created_at")
                    .column_as(crate::entities::organizations::Column::Slug, "org_slug")
                    .column_as(crate::entities::organizations::Column::Name, "org_name")
                    .filter(organization_invitations::Column::Email.eq(email))
                    .filter(organization_invitations::Column::Status.eq("pending"))
                    .order_by_desc(organization_invitations::Column::CreatedAt)
                    .into_model::<InvitationWithOrg>()
                    .all(conn)
                    .await?
            }
            DB::Tx(txn) => {
                OrganizationInvitations::find()
                    .join(
                        JoinType::InnerJoin,
                        crate::entities::organization_invitations::Relation::Organizations.def(),
                    )
                    .select_only()
                    .column_as(organization_invitations::Column::Id, "id")
                    .column_as(organization_invitations::Column::Email, "email")
                    .column_as(organization_invitations::Column::Role, "role")
                    .column_as(organization_invitations::Column::Token, "token")
                    .column_as(organization_invitations::Column::ExpiresAt, "expires_at")
                    .column_as(organization_invitations::Column::CreatedAt, "created_at")
                    .column_as(crate::entities::organizations::Column::Slug, "org_slug")
                    .column_as(crate::entities::organizations::Column::Name, "org_name")
                    .filter(organization_invitations::Column::Email.eq(email))
                    .filter(organization_invitations::Column::Status.eq("pending"))
                    .order_by_desc(organization_invitations::Column::CreatedAt)
                    .into_model::<InvitationWithOrg>()
                    .all(txn)
                    .await?
            }
        };

        Ok(invitations)
    }

    /// List organization invitations with inviter details
    pub async fn list_org_invitations_with_inviter(
        db: DB<'_>,
        org_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InvitationWithInviter>> {
        use crate::entities::prelude::OrganizationInvitations;
        use sea_orm::{JoinType, QueryOrder, QuerySelect, RelationTrait};

        let invitations = OrganizationInvitations::find()
            .join(
                JoinType::InnerJoin,
                organization_invitations::Relation::Users.def(),
            )
            .select_only()
            .column(organization_invitations::Column::Id)
            .column(organization_invitations::Column::Email)
            .column(organization_invitations::Column::Role)
            .column(organization_invitations::Column::Status)
            .column(organization_invitations::Column::Token)
            .column(organization_invitations::Column::ExpiresAt)
            .column(organization_invitations::Column::CreatedAt)
            .column_as(crate::entities::users::Column::Email, "inviter_email")
            .column_as(crate::entities::users::Column::Id, "inviter_id")
            .column_as(
                crate::entities::users::Column::CreatedAt,
                "inviter_created_at",
            )
            .filter(organization_invitations::Column::OrgId.eq(org_id))
            .order_by_desc(organization_invitations::Column::CreatedAt)
            .limit(limit as u64)
            .offset(offset as u64)
            .into_model::<InvitationWithInviter>()
            .all(&db)
            .await?;

        Ok(invitations)
    }

    /// Accept all pending invitations for a given email address.
    /// This should be called within a transaction after a user is created.
    pub async fn accept_all_pending_for_email(
        db: DB<'_>,
        email: &str,
        user_id: &str,
    ) -> Result<()> {
        let pending_invitations = OrganizationInvitations::find()
            .filter(organization_invitations::Column::Email.eq(email))
            .filter(organization_invitations::Column::Status.eq("pending"))
            .all(&db)
            .await?;

        for invitation in pending_invitations {
            let org_id_clone = invitation.org_id.clone();

            let membership_exists =
                MembershipStore::find_by_org_and_user(db.clone(), &invitation.org_id, user_id)
                    .await?
                    .is_some();

            if !membership_exists {
                let member_count =
                    MembershipStore::count_by_org(db.clone(), &invitation.org_id, None).await?;

                let org = Organizations::find()
                    .filter(organizations::Column::Id.eq(&invitation.org_id))
                    .one(&db)
                    .await?
                    .ok_or_else(|| {
                        crate::error::AppError::NotFound("Organization not found".to_string())
                    })?;

                let tier_limit = if let (Some(max_users), Some(_tier_id)) =
                    (org.max_users, org.tier_id.as_ref())
                {
                    max_users as i64
                } else if let Some(tier_id) = org.tier_id.as_ref() {
                    let tier = OrganizationTierStore::find_by_id(db.clone(), tier_id)
                        .await?
                        .ok_or_else(|| {
                            crate::error::AppError::NotFound("Tier not found".to_string())
                        })?;

                    tier.default_max_users as i64
                } else {
                    DEFAULT_MAX_USERS
                };

                if member_count >= tier_limit as u64 {
                    return Err(crate::error::AppError::BadRequest(
                        "Team limit reached".to_string(),
                    ));
                }

                MembershipStore::create(db.clone(), &invitation.org_id, user_id, &invitation.role)
                    .await?;

                PermissionsStore::grant(
                    db.clone(),
                    RelationTuple::user(
                        "organization".to_string(),
                        invitation.org_id.clone(),
                        invitation.role.clone(),
                        user_id.to_string(),
                    ),
                )
                .await?;
            }

            // Update invitation status
            let mut invitation_active: organization_invitations::ActiveModel = invitation.into();
            invitation_active.status = Set("accepted".to_string());
            invitation_active.update(&db).await?;

            tracing::info!(
                "Automatically accepted invitation for user {} to organization {}",
                user_id,
                org_id_clone
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{organization_invitations, prelude::OrganizationInvitations};
    use crate::store::{
        memberships::MembershipStore, organizations::OrganizationStore,
        permissions::PermissionsStore, users::UserStore, DB,
    };
    use chrono::{Duration, Utc};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, EntityTrait, Set};

    async fn setup_db() -> sea_orm::DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    async fn create_user(
        db: &sea_orm::DatabaseConnection,
        email: &str,
    ) -> crate::entities::users::Model {
        UserStore::find_or_create_with_options(
            DB::Conn(db),
            email,
            crate::store::users::UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user")
        .0
    }

    async fn create_invitation(
        db: &sea_orm::DatabaseConnection,
        org_id: &str,
        invited_by: &str,
        email: &str,
        role: &str,
    ) -> organization_invitations::Model {
        organization_invitations::ActiveModel {
            id: Set(format!("invitation-{role}")),
            org_id: Set(org_id.to_string()),
            email: Set(email.to_string()),
            role: Set(role.to_string()),
            invited_by: Set(invited_by.to_string()),
            status: Set("pending".to_string()),
            token: Set(format!("token-{role}")),
            expires_at: Set((Utc::now() + Duration::days(1)).naive_utc()),
            created_at: Set(Utc::now().naive_utc()),
        }
        .insert(db)
        .await
        .expect("create invitation")
    }

    #[tokio::test]
    async fn accepting_pending_invitation_applies_role_and_consumes_invitation_once() {
        let db = setup_db().await;
        let owner = create_user(&db, "owner@example.com").await;
        let invitee = create_user(&db, "invitee@example.com").await;
        let (org, _owner_membership) =
            OrganizationStore::create_with_owner(DB::Conn(&db), "acme", "Acme", &owner.id, None)
                .await
                .expect("create org");
        let invitation =
            create_invitation(&db, &org.id, &owner.id, &invitee.email, "billing-admin").await;

        InvitationStore::accept_all_pending_for_email(DB::Conn(&db), &invitee.email, &invitee.id)
            .await
            .expect("accept invitation");
        InvitationStore::accept_all_pending_for_email(DB::Conn(&db), &invitee.email, &invitee.id)
            .await
            .expect("second accept is idempotent");

        let membership = MembershipStore::find_by_org_and_user(DB::Conn(&db), &org.id, &invitee.id)
            .await
            .expect("find membership")
            .expect("membership exists");
        assert_eq!(membership.role, "billing-admin");

        let member_count = MembershipStore::count_by_org(DB::Conn(&db), &org.id, None)
            .await
            .expect("count members");
        assert_eq!(member_count, 2);

        assert!(PermissionsStore::check(
            DB::Conn(&db),
            "organization",
            &org.id,
            "billing-admin",
            &invitee.id,
        )
        .await
        .expect("check permission"));

        let stored_invitation = OrganizationInvitations::find_by_id(invitation.id)
            .one(&db)
            .await
            .expect("load invitation")
            .expect("invitation exists");
        assert_eq!(stored_invitation.status, "accepted");

        let pending_count =
            InvitationStore::count_pending_by_org_and_email(DB::Conn(&db), &org.id, &invitee.email)
                .await
                .expect("count pending invitations");
        assert_eq!(pending_count, 0);
    }
}

use crate::entities::prelude::OrganizationInvitations;
use crate::entities::{memberships, organization_invitations};
use crate::error::Result;
use crate::store::DB;
use chrono::NaiveDateTime;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter,
    QuerySelect, Set,
};
use uuid::Uuid;

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

            // Create membership
            let new_membership = memberships::ActiveModel {
                id: Set(Uuid::new_v4().to_string()),
                org_id: Set(invitation.org_id.clone()),
                user_id: Set(user_id.to_string()),
                role: Set(invitation.role.clone()),
                ..Default::default()
            };
            new_membership.insert(&db).await?;

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

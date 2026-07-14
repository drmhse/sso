#![allow(dead_code)]

use crate::auth::sso::Provider;
use crate::entities::login_events;
use crate::services::audit_actor::AuditHandle;
use crate::services::risk_engine::RiskAssessment;
use sea_orm::Set;
use uuid::Uuid;

/// Durably enqueue a login event for analytics and audit reconciliation.
/// Includes risk assessment data if available
pub async fn record_login_event(
    audit_actor: &AuditHandle,
    user_id: &str,
    org_id: Option<&str>,
    service_id: Option<&str>,
    provider: Provider,
    risk_assessment: Option<&RiskAssessment>,
) -> anyhow::Result<()> {
    let mut event_model = login_events::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_id: Set(user_id.to_string()),
        org_id: Set(org_id.map(|s| s.to_string())),
        service_id: Set(service_id.map(|s| s.to_string())),
        provider: Set(provider.as_str().to_string()),
        ..Default::default()
    };

    if let Some(risk) = risk_assessment {
        event_model.risk_score = Set(Some(risk.score));
        event_model.risk_factors = Set(Some(
            serde_json::to_string(&risk.factors).unwrap_or_default(),
        ));

        if let Some(ref loc) = risk.location {
            event_model.geo_country = Set(Some(loc.country.clone()));
            event_model.geo_city = Set(loc.city.clone());
            event_model.geo_lat = Set(Some(loc.latitude));
            event_model.geo_long = Set(Some(loc.longitude));
        }
    }

    // Await the durable outbox insert; final-table delivery is asynchronous.
    audit_actor.log_login(event_model).await?;
    Ok(())
}

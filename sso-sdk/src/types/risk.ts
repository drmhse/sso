export interface GeoLocation {
  country: string;
  city?: string;
  latitude: number;
  longitude: number;
}

export type RiskAction = 'allow' | 'challenge_mfa' | 'block' | 'log_only';

export interface RiskAssessment {
  score: number;
  factors: string[];
  action: RiskAction;
  location?: GeoLocation;
}

export interface RiskEventResponse {
  id: string;
  user_id: string;
  user_email?: string;
  created_at: string;
  risk_score: number;
  risk_factors: string[];
  risk_action: RiskAction | string;
  geo_country?: string;
  geo_city?: string;
  geo_lat?: number;
  geo_long?: number;
  ip_address?: string;
  provider: string;
}

export interface RiskEventsQuery {
  page?: number;
  limit?: number;
  min_score?: number;
}

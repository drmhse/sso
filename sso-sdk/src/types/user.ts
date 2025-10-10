/**
 * User subscription details
 */
export interface Subscription {
  service: string;
  plan: string;
  features: string[];
  status: string;
  current_period_end?: string;
}

/**
 * Update user profile payload
 */
export interface UpdateUserProfilePayload {
  email?: string;
}

/**
 * Social identity linked to the user
 */
export interface Identity {
  provider: string;
}

/**
 * Response when starting a social account link
 */
export interface StartLinkResponse {
  authorization_url: string;
}

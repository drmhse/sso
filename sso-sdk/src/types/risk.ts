/**
 * Risk assessment and engine types
 */

/**
 * Risk score levels
 */
export type RiskScore = number;

/**
 * Risk assessment results from the risk engine
 */
export interface RiskAssessment {
  /** Overall risk score (0-100, higher is more risky) */
  score: RiskScore;
  /** Action to take based on risk assessment */
  action: RiskAction;
  /** Specific risk factors that contributed to the score */
  factors: RiskFactor[];
  /** Geolocation data if available */
  location?: GeolocationData;
  /** When the assessment was performed */
  assessedAt: string;
  /** Additional metadata about the assessment */
  metadata?: Record<string, unknown>;
}

/**
 * Risk actions the engine can recommend
 */
export enum RiskAction {
  /** Allow the authentication to proceed */
  ALLOW = 'allow',
  /** Log only - allow but monitor */
  LOG_ONLY = 'log_only',
  /** Require additional verification (MFA) */
  CHALLENGE_MFA = 'challenge_mfa',
  /** Block the authentication attempt */
  BLOCK = 'block'
}

/**
 * Individual risk factors that contribute to overall risk score
 */
export interface RiskFactor {
  /** Type of risk factor */
  type: RiskFactorType;
  /** How much this factor contributes to the score */
  weight: number;
  /** Human-readable description */
  description: string;
  /** Additional data about this factor */
  data?: Record<string, unknown>;
}

/**
 * Types of risk factors the engine can detect
 */
export enum RiskFactorType {
  /** Unknown IP address or never seen before */
  NEW_IP = 'new_ip',
  /** IP from high-risk country or region */
  HIGH_RISK_LOCATION = 'high_risk_location',
  /** Impossible travel - login from geographically impossible locations */
  IMPOSSIBLE_TRAVEL = 'impossible_travel',
  /** New device or browser fingerprint */
  NEW_DEVICE = 'new_device',
  /** Multiple failed login attempts */
  FAILED_ATTEMPTS = 'failed_attempts',
  /** Login from unusual time of day */
  UNUSUAL_TIME = 'unusual_time',
  /** Suspicious user agent or bot patterns */
  SUSPICIOUS_USER_AGENT = 'suspicious_user_agent',
  /** Tor exit node or VPN detected */
  ANONYMOUS_NETWORK = 'anonymous_network',
  /** Account is new (recently created) */
  NEW_ACCOUNT = 'new_account',
  /** Account has suspicious activity history */
  SUSPICIOUS_HISTORY = 'suspicious_history',
  /** Velocity-based detection (too many actions) */
  HIGH_VELOCITY = 'high_velocity',
  /** Custom rule triggered */
  CUSTOM_RULE = 'custom_rule'
}

/**
 * Geolocation data for risk assessment
 */
export interface GeolocationData {
  /** Two-letter ISO country code */
  country: string;
  /** City name if available */
  city?: string;
  /** Region/state if available */
  region?: string;
  /** Latitude coordinate */
  latitude?: number;
  /** Longitude coordinate */
  longitude?: number;
  /** ISP or organization name */
  isp?: string;
  /** Whether this is a known VPN/proxy */
  isVpn?: boolean;
  /** Whether this is a Tor exit node */
  isTor?: boolean;
}

/**
 * Context provided to risk engine for assessment
 */
export interface RiskContext {
  /** User ID being authenticated */
  userId: string;
  /** Organization ID if applicable */
  orgId?: string;
  /** IP address of the request */
  ipAddress: string;
  /** User agent string */
  userAgent: string;
  /** Device fingerprint or cookie if available */
  deviceCookie?: string;
  /** Authentication method being used */
  authMethod: AuthMethod;
  /** Additional context data */
  metadata?: Record<string, unknown>;
}

/**
 * Authentication methods for risk assessment
 */
export enum AuthMethod {
  /** Email and password */
  PASSWORD = 'password',
  /** OAuth provider (Google, GitHub, etc.) */
  OAUTH = 'oauth',
  /** WebAuthn passkeys */
  PASSKEY = 'passkey',
  /** Magic link email */
  MAGIC_LINK = 'magic_link',
  /** Multi-factor authentication */
  MFA = 'mfa',
  /** SAML SSO */
  SAML = 'saml'
}

/**
 * Risk engine configuration for organizations
 */
export interface RiskEngineConfig {
  /** Enable/disable risk engine */
  enabled: boolean;
  /** Risk score threshold for blocking */
  blockThreshold: RiskScore;
  /** Risk score threshold for requiring MFA */
  mfaThreshold: RiskScore;
  /** Which risk factors to consider */
  enabledFactors: RiskFactorType[];
  /** Custom rules and weights */
  customRules?: RiskRule[];
  /** How long to remember trusted devices */
  deviceTrustDuration: number; // in seconds
  /** Whether to enable location-based risk assessment */
  enableLocationTracking: boolean;
  /** Max failed attempts before increased risk */
  maxFailedAttempts: number;
  /** Time window for velocity checks */
  velocityWindow: number; // in seconds
}

/**
 * Custom risk rule definition
 */
export interface RiskRule {
  /** Unique rule identifier */
  id: string;
  /** Rule name for display */
  name: string;
  /** Rule description */
  description: string;
  /** Condition to trigger the rule */
  condition: RiskRuleCondition;
  /** Action to take when rule triggers */
  action: RiskAction;
  /** How much weight this rule carries */
  weight: number;
  /** Whether the rule is enabled */
  enabled: boolean;
}

/**
 * Risk rule condition
 */
export interface RiskRuleCondition {
  /** Field to check */
  field: string;
  /** Operator for comparison */
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'in' | 'contains' | 'regex';
  /** Value to compare against */
  value: unknown;
  /** Additional conditions (AND logic) */
  and?: RiskRuleCondition[];
  /** Alternative conditions (OR logic) */
  or?: RiskRuleCondition[];
}

/**
 * Device trust information
 */
export interface DeviceTrust {
  /** Device ID */
  deviceId: string;
  /** User ID this device belongs to */
  userId: string;
  /** Device name or description */
  deviceName: string;
  /** When the device was first seen */
  firstSeenAt: string;
  /** When the device was last used */
  lastSeenAt: string;
  /** When the device trust expires */
  expiresAt: string;
  /** IP address when device was registered */
  registrationIp?: string;
  /** Risk score for this device */
  riskScore: RiskScore;
  /** Whether this device is currently trusted */
  isTrusted: boolean;
}

/**
 * Risk event for logging and monitoring
 */
export interface RiskEvent {
  /** Unique event ID */
  id: string;
  /** User ID involved */
  userId: string;
  /** Organization ID if applicable */
  orgId?: string;
  /** Risk assessment that triggered this event */
  assessment: RiskAssessment;
  /** Authentication context */
  context: RiskContext;
  /** When the event occurred */
  timestamp: string;
  /** Event outcome */
  outcome: RiskEventOutcome;
  /** Additional event metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Risk event outcomes
 */
export enum RiskEventOutcome {
  /** Authentication was allowed */
  ALLOWED = 'allowed',
  /** Authentication was blocked */
  BLOCKED = 'blocked',
  /** Additional verification was required */
  CHALLENGED = 'challenged',
  /** Event was logged but no action taken */
  LOGGED = 'logged'
}

/**
 * Risk engine analytics and reporting
 */
export interface RiskAnalytics {
  /** Total risk assessments in time period */
  totalAssessments: number;
  /** Risk score distribution */
  scoreDistribution: {
    low: number;      // 0-25
    medium: number;   // 26-50
    high: number;     // 51-75
    critical: number; // 76-100
  };
  /** Most common risk factors */
  topRiskFactors: Array<{
    factor: RiskFactorType;
    count: number;
    percentage: number;
  }>;
  /** Blocked authentication attempts */
  blockedAttempts: number;
  /** MFA challenges issued */
  mfaChallenges: number;
  /** Geographic risk data */
  locationRisk: Array<{
    country: string;
    riskCount: number;
    riskScore: number;
  }>;
  /** Time-based risk patterns */
  temporalPatterns: {
    hourly: number[];    // Risk by hour of day
    daily: number[];     // Risk by day of week
  };
}

/**
 * Risk enforcement modes
 */
export type RiskEnforcementMode = 'log_only' | 'monitor' | 'block' | 'challenge_mfa';

/**
 * Organization risk settings
 */
export interface RiskSettings {
  enforcement_mode: RiskEnforcementMode;
  low_threshold: number;
  medium_threshold: number;
  new_device_score: number;
  impossible_travel_score: number;
  velocity_threshold: number;
  velocity_score: number;
}
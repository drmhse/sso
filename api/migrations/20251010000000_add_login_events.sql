-- ============================================================================
-- LOGIN EVENTS TRACKING
-- Track all successful logins for analytics and audit purposes
-- ============================================================================

-- Login events table
CREATE TABLE login_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    provider TEXT NOT NULL, -- 'github', 'google', 'microsoft'
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for analytics queries
CREATE INDEX idx_login_events_user ON login_events(user_id);
CREATE INDEX idx_login_events_service ON login_events(service_id);
CREATE INDEX idx_login_events_provider ON login_events(provider);
CREATE INDEX idx_login_events_created ON login_events(created_at DESC);
CREATE INDEX idx_login_events_service_created ON login_events(service_id, created_at DESC);

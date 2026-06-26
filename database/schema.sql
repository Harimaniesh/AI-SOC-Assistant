-- PostgreSQL database schema for AI SOC Assistant

-- Create Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'Analyst' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Create LogFiles table
CREATE TABLE IF NOT EXISTS log_files (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255) UNIQUE NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    file_size INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'Pending' NOT NULL,
    uploaded_by INTEGER NOT NULL,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_log_files_uploader FOREIGN KEY (uploaded_by) REFERENCES users (id) ON DELETE CASCADE
);

-- Create Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    log_file_id INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    source_ip VARCHAR(50) NOT NULL,
    destination_ip VARCHAR(50) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity INTEGER NOT NULL,
    mitre_id VARCHAR(50),
    status VARCHAR(50) DEFAULT 'New' NOT NULL,
    description TEXT,
    target_system VARCHAR(255),
    raw_log_payload TEXT,
    CONSTRAINT fk_alerts_log_file FOREIGN KEY (log_file_id) REFERENCES log_files (id) ON DELETE SET NULL
);

-- Create Incident Reports table
CREATE TABLE IF NOT EXISTS incident_reports (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER UNIQUE NOT NULL,
    summary TEXT NOT NULL,
    recommended_remediation TEXT NOT NULL,
    pdf_path VARCHAR(512),
    created_by INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_incident_reports_alert FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_reports_creator FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
);

-- Indexes for performance optimization on search & filtering
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_type ON alerts (threat_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_log_files_uploaded_by ON log_files (uploaded_by);
CREATE INDEX IF NOT EXISTS idx_incident_reports_alert_id ON incident_reports (alert_id);

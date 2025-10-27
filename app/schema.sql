CREATE DATABASE IF NOT EXISTS nessus_data CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE nessus_data;

CREATE TABLE IF NOT EXISTS scans (
  scan_id INT PRIMARY KEY,
  name VARCHAR(255),
  uuid VARCHAR(128),
  targets TEXT,
  folder_id INT,
  last_seen BIGINT
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS processed_history (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  scan_id INT NOT NULL,
  history_id INT NOT NULL,
  scan_uuid VARCHAR(128),
  scan_name VARCHAR(255),
  targets TEXT,
  status VARCHAR(32),
  scan_start BIGINT,
  scan_end BIGINT,
  last_modification BIGINT,
  UNIQUE KEY uq_scan_history (scan_id, history_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS hosts (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  scan_id INT NOT NULL,
  history_id INT NOT NULL,
  host_id INT NOT NULL,
  hostname VARCHAR(255),
  critical INT DEFAULT 0,
  high INT DEFAULT 0,
  medium INT DEFAULT 0,
  low INT DEFAULT 0,
  info INT DEFAULT 0,
  UNIQUE KEY uq_host (scan_id, history_id, host_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS plugins (
  plugin_id INT PRIMARY KEY,
  plugin_name VARCHAR(255),
  plugin_family VARCHAR(255)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS findings (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  scan_id INT NOT NULL,
  history_id INT NOT NULL,
  plugin_id INT NOT NULL,
  hostname VARCHAR(255) NULL,
  severity INT NOT NULL,
  count INT DEFAULT 0,
  cpe VARCHAR(255),
  vpr_score DECIMAL(4,2),
  epss_score DECIMAL(6,4),
  offline TINYINT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  UNIQUE KEY uq_finding (scan_id, history_id, plugin_id, hostname),
  KEY idx_history (scan_id, history_id),

  CONSTRAINT fk_finding_plugin FOREIGN KEY (plugin_id) REFERENCES plugins(plugin_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cves (
  cve_id VARCHAR(32) PRIMARY KEY,
  cvss_v2 DECIMAL(3,1),
  cvss_v3 DECIMAL(3,1),
  severity VARCHAR(16),
  description TEXT
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS finding_cves (
  finding_id BIGINT NOT NULL,
  cve_id VARCHAR(32) NOT NULL,
  PRIMARY KEY (finding_id, cve_id),
  CONSTRAINT fk_fc_finding FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE,
  CONSTRAINT fk_fc_cve FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE RESTRICT
) ENGINE=InnoDB;

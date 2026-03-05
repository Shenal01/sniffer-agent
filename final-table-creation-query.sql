CREATE DATABASE IF NOT EXISTS exfiltrap;

USE exfiltrap;

CREATE TABLE IF NOT EXISTS dns_all_plain (
  plain_id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT 'Primary Key. Auto-increments for C++ DB Exporter',
  flow_id BIGINT NULL COMMENT 'Nullable. Groups queries into a flow instance',

  timestamp DATETIME,
  src_ip VARCHAR(45),
  src_port INT,
  dst_ip VARCHAR(45),
  dst_port INT,
  traffic_type VARCHAR(50),

  dns_domain_name VARCHAR(255),
  dns_domain_name_length INT,
  dns_second_level_domain VARCHAR(255),
  dns_subdomain_name_length INT,
  dns_top_level_domain VARCHAR(50),

  -- Lexical Features
  `features.lexical.entropy` FLOAT,
  `features.lexical.length` FLOAT,
  `features.lexical.lex_compression_ratio` FLOAT,
  `features.lexical.lex_first_label_has_digit` BOOLEAN,
  `features.lexical.lex_label_count` INT,
  `features.lexical.lex_len` INT,
  `features.lexical.lex_max_label_len` INT,
  `features.lexical.lex_tool_generated` BOOLEAN,
  `features.lexical.ratio_alpha` FLOAT,
  `features.lexical.ratio_digit` FLOAT,
  `features.lexical.ratio_hyphen` FLOAT,
  `features.lexical.ratio_other` FLOAT,

  -- Behavioural Features
  `features.behavioural.character_entropy` FLOAT,
  `features.behavioural.conv_freq_vowels_consonants` FLOAT,
  `features.behavioural.dns_domain_name_length` INT,
  `features.behavioural.dns_subdomain_name_length` INT,
  `features.behavioural.hour` INT,
  `features.behavioural.is_night` BOOLEAN,
  `features.behavioural.max_continuous_alphabet_len` INT,
  `features.behavioural.max_continuous_consonants_len` INT,
  `features.behavioural.max_continuous_numeric_len` INT,
  `features.behavioural.max_continuous_same_alphabet_len` INT,
  `features.behavioural.numerical_percentage` FLOAT,
  `features.behavioural.vowels_consonant_ratio` FLOAT,
  
  `raw` BIGINT,

  -- ============================================================== --
  -- MASTER MERGE: C++ ML DNS ABUSE DETECTION FEATURES
  -- ============================================================== --
  `features.dns_abuse.dns_amplification_factor` DOUBLE,
  `features.dns_abuse.query_response_ratio` DOUBLE,
  `features.dns_abuse.dns_any_query_ratio` DOUBLE,
  `features.dns_abuse.dns_txt_query_ratio` DOUBLE,
  `features.dns_abuse.dns_response_inconsistency` DOUBLE,
  `features.dns_abuse.dns_queries_per_second` DOUBLE,
  `features.dns_abuse.port_53_traffic_ratio` DOUBLE,
  
  `features.dns_abuse.flow_bytes_per_sec` DOUBLE,
  `features.dns_abuse.flow_packets_per_sec` DOUBLE,
  `features.dns_abuse.fwd_packets_per_sec` DOUBLE,
  `features.dns_abuse.bwd_packets_per_sec` DOUBLE,
  
  `features.dns_abuse.flow_duration` DOUBLE,
  `features.dns_abuse.total_fwd_packets` INT,
  `features.dns_abuse.total_bwd_packets` INT,
  `features.dns_abuse.total_fwd_bytes` BIGINT,
  `features.dns_abuse.total_bwd_bytes` BIGINT,
  
  `features.dns_abuse.dns_total_queries` INT,
  `features.dns_abuse.dns_total_responses` INT,
  `features.dns_abuse.dns_response_size` BIGINT,
  
  `features.dns_abuse.flow_iat_mean` DOUBLE,
  `features.dns_abuse.flow_iat_std` DOUBLE,
  `features.dns_abuse.flow_iat_min` DOUBLE,
  `features.dns_abuse.flow_iat_max` DOUBLE,
  `features.dns_abuse.fwd_iat_mean` DOUBLE,
  `features.dns_abuse.bwd_iat_mean` DOUBLE,
  
  `features.dns_abuse.fwd_packet_length_mean` DOUBLE,
  `features.dns_abuse.bwd_packet_length_mean` DOUBLE,
  `features.dns_abuse.packet_size_std` DOUBLE,
  `features.dns_abuse.flow_length_min` BIGINT,
  `features.dns_abuse.flow_length_max` BIGINT,
  `features.dns_abuse.average_packet_size` DOUBLE,
  `features.dns_abuse.response_time_variance` DOUBLE,
  
  `features.dns_abuse.large_packet_ratio` DOUBLE,
  `features.dns_abuse.medium_packet_ratio` DOUBLE,
  `features.dns_abuse.small_packet_ratio` DOUBLE,
  `features.dns_abuse.sni_entropy` DOUBLE,
  `features.dns_abuse.is_known_doh_server` INT,
  `features.dns_abuse.encrypted_payload_size_variance` DOUBLE,

  -- Python ML Resolving Target
  dns_abuse_prediction INT DEFAULT NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX idx_timestamp ON dns_all_plain(timestamp);
CREATE INDEX idx_flow_id ON dns_all_plain(flow_id);
CREATE INDEX idx_src_ip ON dns_all_plain(src_ip);
CREATE INDEX idx_dns_domain_name ON dns_all_plain(dns_domain_name);

-- Performance Indexes for Python ML Poller
CREATE INDEX idx_traffic_type_plain ON dns_all_plain(traffic_type);
CREATE INDEX idx_prediction_plain ON dns_all_plain(dns_abuse_prediction);


CREATE TABLE IF NOT EXISTS dns_all_doh (
  doh_id BIGINT PRIMARY KEY AUTO_INCREMENT COMMENT 'Primary Key. Auto-increments for C++ DB Exporter',

  timestamp DATETIME,
  `flow_features.start_ts` DATETIME,
  `flow_features.end_ts` DATETIME,

  client_ip VARCHAR(45),
  client_port INT,
  server_ip VARCHAR(45),
  server_port INT,
  traffic_type VARCHAR(50),

  -- Raw Flow Metrics
  `flow_features.Duration` FLOAT,
  `flow_features.FlowBytesReceived` FLOAT,
  `flow_features.FlowBytesSent` FLOAT,
  `flow_features.FlowReceivedRate` FLOAT,
  `flow_features.FlowSentRate` FLOAT,
  `flow_features.PacketLengthCoefficientofVariation` FLOAT,
  `flow_features.PacketLengthMean` FLOAT,
  `flow_features.PacketLengthMedian` FLOAT,
  `flow_features.PacketLengthMode` FLOAT,
  `flow_features.PacketLengthSkewFromMedian` FLOAT,
  `flow_features.PacketLengthSkewFromMode` FLOAT,
  `flow_features.PacketLengthStandardDeviation` FLOAT,
  `flow_features.PacketLengthVariance` FLOAT,
  `flow_features.PacketTimeCoefficientofVariation` FLOAT,
  `flow_features.PacketTimeMean` FLOAT,
  `flow_features.PacketTimeMedian` FLOAT,
  `flow_features.PacketTimeMode` FLOAT,
  `flow_features.PacketTimeSkewFromMedian` FLOAT,
  `flow_features.PacketTimeSkewFromMode` FLOAT,
  `flow_features.PacketTimeStandardDeviation` FLOAT,
  `flow_features.PacketTimeVariance` FLOAT,
  `flow_features.ResponseTimeTimeCoefficientofVariation` FLOAT,
  `flow_features.ResponseTimeTimeMean` FLOAT,
  `flow_features.ResponseTimeTimeMedian` FLOAT,
  `flow_features.ResponseTimeTimeMode` FLOAT,
  `flow_features.ResponseTimeTimeSkewFromMedian` FLOAT,
  `flow_features.ResponseTimeTimeSkewFromMode` FLOAT,
  `flow_features.ResponseTimeTimeStandardDeviation` FLOAT,
  `flow_features.ResponseTimeTimeVariance` FLOAT,

  -- Replicated ML-Specific Extracted Flow Metrics (RF)
  `features.behavioural_rf.Duration` FLOAT,
  `features.behavioural_rf.FlowBytesReceived` FLOAT,
  `features.behavioural_rf.FlowBytesSent` FLOAT,
  `features.behavioural_rf.FlowReceivedRate` FLOAT,
  `features.behavioural_rf.FlowSentRate` FLOAT,
  `features.behavioural_rf.PacketLengthCoefficientofVariation` FLOAT,
  `features.behavioural_rf.PacketLengthMean` FLOAT,
  `features.behavioural_rf.PacketLengthMedian` FLOAT,
  `features.behavioural_rf.PacketLengthMode` FLOAT,
  `features.behavioural_rf.PacketLengthSkewFromMedian` FLOAT,
  `features.behavioural_rf.PacketLengthSkewFromMode` FLOAT,
  `features.behavioural_rf.PacketLengthStandardDeviation` FLOAT,
  `features.behavioural_rf.PacketLengthVariance` FLOAT,
  `features.behavioural_rf.PacketTimeCoefficientofVariation` FLOAT,
  `features.behavioural_rf.PacketTimeMean` FLOAT,
  `features.behavioural_rf.PacketTimeMedian` FLOAT,
  `features.behavioural_rf.PacketTimeMode` FLOAT,
  `features.behavioural_rf.PacketTimeSkewFromMedian` FLOAT,
  `features.behavioural_rf.PacketTimeSkewFromMode` FLOAT,
  `features.behavioural_rf.PacketTimeStandardDeviation` FLOAT,
  `features.behavioural_rf.PacketTimeVariance` FLOAT,

  -- Replicated ML-Specific Extracted Flow Metrics (IF)
  `features.behavioural_if.Duration` FLOAT,
  `features.behavioural_if.FlowBytesReceived` FLOAT,
  `features.behavioural_if.FlowBytesSent` FLOAT,
  `features.behavioural_if.FlowReceivedRate` FLOAT,
  `features.behavioural_if.FlowSentRate` FLOAT,
  `features.behavioural_if.PacketLengthCoefficientofVariation` FLOAT,
  `features.behavioural_if.PacketLengthMean` FLOAT,
  `features.behavioural_if.PacketLengthMedian` FLOAT,
  `features.behavioural_if.PacketLengthMode` FLOAT,
  `features.behavioural_if.PacketLengthSkewFromMedian` FLOAT,
  `features.behavioural_if.PacketLengthSkewFromMode` FLOAT,
  `features.behavioural_if.PacketLengthStandardDeviation` FLOAT,
  `features.behavioural_if.PacketLengthVariance` FLOAT,
  `features.behavioural_if.PacketTimeCoefficientofVariation` FLOAT,
  `features.behavioural_if.PacketTimeMean` FLOAT,
  `features.behavioural_if.PacketTimeMedian` FLOAT,
  `features.behavioural_if.PacketTimeMode` FLOAT,
  `features.behavioural_if.PacketTimeSkewFromMedian` FLOAT,
  `features.behavioural_if.PacketTimeSkewFromMode` FLOAT,
  `features.behavioural_if.PacketTimeStandardDeviation` FLOAT,
  `features.behavioural_if.PacketTimeVariance` FLOAT,
  
  `raw` BIGINT,

  -- ============================================================== --
  -- MASTER MERGE: C++ ML DNS ABUSE DETECTION FEATURES
  -- ============================================================== --
  `features.dns_abuse.dns_amplification_factor` DOUBLE,
  `features.dns_abuse.query_response_ratio` DOUBLE,
  `features.dns_abuse.dns_any_query_ratio` DOUBLE,
  `features.dns_abuse.dns_txt_query_ratio` DOUBLE,
  `features.dns_abuse.dns_response_inconsistency` DOUBLE,
  `features.dns_abuse.dns_queries_per_second` DOUBLE,
  `features.dns_abuse.port_53_traffic_ratio` DOUBLE,
  
  `features.dns_abuse.flow_bytes_per_sec` DOUBLE,
  `features.dns_abuse.flow_packets_per_sec` DOUBLE,
  `features.dns_abuse.fwd_packets_per_sec` DOUBLE,
  `features.dns_abuse.bwd_packets_per_sec` DOUBLE,
  
  `features.dns_abuse.flow_duration` DOUBLE,
  `features.dns_abuse.total_fwd_packets` INT,
  `features.dns_abuse.total_bwd_packets` INT,
  `features.dns_abuse.total_fwd_bytes` BIGINT,
  `features.dns_abuse.total_bwd_bytes` BIGINT,
  
  `features.dns_abuse.dns_total_queries` INT,
  `features.dns_abuse.dns_total_responses` INT,
  `features.dns_abuse.dns_response_size` BIGINT,
  
  `features.dns_abuse.flow_iat_mean` DOUBLE,
  `features.dns_abuse.flow_iat_std` DOUBLE,
  `features.dns_abuse.flow_iat_min` DOUBLE,
  `features.dns_abuse.flow_iat_max` DOUBLE,
  `features.dns_abuse.fwd_iat_mean` DOUBLE,
  `features.dns_abuse.bwd_iat_mean` DOUBLE,
  
  `features.dns_abuse.fwd_packet_length_mean` DOUBLE,
  `features.dns_abuse.bwd_packet_length_mean` DOUBLE,
  `features.dns_abuse.packet_size_std` DOUBLE,
  `features.dns_abuse.flow_length_min` BIGINT,
  `features.dns_abuse.flow_length_max` BIGINT,
  `features.dns_abuse.average_packet_size` DOUBLE,
  `features.dns_abuse.response_time_variance` DOUBLE,
  
  `features.dns_abuse.large_packet_ratio` DOUBLE,
  `features.dns_abuse.medium_packet_ratio` DOUBLE,
  `features.dns_abuse.small_packet_ratio` DOUBLE,
  `features.dns_abuse.sni_entropy` DOUBLE,
  `features.dns_abuse.is_known_doh_server` INT,
  `features.dns_abuse.encrypted_payload_size_variance` DOUBLE,

  -- Python ML Resolving Target
  dns_abuse_prediction INT DEFAULT NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE INDEX idx_timestamp_doh ON dns_all_doh(timestamp);
CREATE INDEX idx_start_ts ON dns_all_doh(`flow_features.start_ts`);
CREATE INDEX idx_client_ip ON dns_all_doh(client_ip);
CREATE INDEX idx_server_ip ON dns_all_doh(server_ip);

-- Performance Indexes for Python ML Poller
CREATE INDEX idx_traffic_type_doh ON dns_all_doh(traffic_type);
CREATE INDEX idx_prediction_doh ON dns_all_doh(dns_abuse_prediction);


-- ============================================================== --
-- CORE ML ISOLATION DASHBOARD (Target For Python XGBoost Pipeline)
-- ============================================================== --
CREATE TABLE IF NOT EXISTS dns_abuse_security_alerts LIKE dns_all_plain;



-- ============================================================== --
-- LEGACY COMPONENT TABLES FROM ORIGINAL SCHEMA
-- ============================================================== --

CREATE TABLE IF NOT EXISTS dns_tunneling_plain (
  plain_id BIGINT PRIMARY KEY,
  component VARCHAR(100),
  time_bucket VARCHAR(100),

  `features.behavioural.done` BOOLEAN,
  `features.lexical.done` BOOLEAN,

  `pipeline_status.classified_behavioural` BOOLEAN,
  `pipeline_status.classified_lexical` BOOLEAN,
  `pipeline_status.event_aggregated` BOOLEAN,
  `pipeline_status.features_extracted` BOOLEAN,
  `pipeline_status.fusion_done` BOOLEAN,
  `pipeline_status.raw_ingested` BOOLEAN,

  `predictions.lexical` VARCHAR(100),
  `predictions.behavioural` VARCHAR(100),

  fusion_reason VARCHAR(255),
  `predictions.fused` VARCHAR(100),
  `predictions.risk_score` FLOAT,
  `predictions.severity` VARCHAR(50),

  final_decision VARCHAR(50),

  CONSTRAINT fk_dns_tunneling_plain_all_plain
    FOREIGN KEY (plain_id) REFERENCES dns_all_plain(plain_id)
    ON UPDATE CASCADE
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dns_tunneling_doh (
  doh_id BIGINT PRIMARY KEY,
  component VARCHAR(100),
  time_bucket VARCHAR(100),

  `features.behavioural_if.done` BOOLEAN,
  `features.behavioural_rf.done` BOOLEAN,

  `pipeline_status.classified_if` BOOLEAN,
  `pipeline_status.classified_rf` BOOLEAN,
  `pipeline_status.event_aggregated` BOOLEAN,
  `pipeline_status.features_extracted` BOOLEAN,
  `pipeline_status.features_extracted_if` BOOLEAN,
  `pipeline_status.features_extracted_rf` BOOLEAN,
  `pipeline_status.fusion_done` BOOLEAN,
  `pipeline_status.raw_ingested` BOOLEAN,

  `predictions.if.label` VARCHAR(100),
  `predictions.if.score` FLOAT,
  `predictions.if.threshold` FLOAT,

  `predictions.rf.label` VARCHAR(100),
  `predictions.rf.score` FLOAT,
  `predictions.rf.threshold` FLOAT,

  `predictions.fused.label` VARCHAR(100),
  `predictions.fused.reason` VARCHAR(255),
  `predictions.fused.risk_score` FLOAT,
  `predictions.fused.score` FLOAT,
  `predictions.fused.severity` VARCHAR(50),

  `predictions.risk_score` FLOAT,
  `predictions.severity` VARCHAR(50),

  final_decision VARCHAR(50),

  CONSTRAINT fk_dns_tunneling_doh_all_doh
    FOREIGN KEY (doh_id) REFERENCES dns_all_doh(doh_id)
    ON UPDATE CASCADE
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dns_tunnel_events (
  event_id BIGINT PRIMARY KEY,

  plain_id BIGINT NULL COMMENT 'Pointer to Plain packet if alert originated from Plain text',
  doh_id BIGINT NULL COMMENT 'Pointer to DoH flow if alert originated from Encrypted traffic',

  client_ip VARCHAR(45),
  server_ip VARCHAR(45),
  component VARCHAR(100),
  count INT,
  doh_key VARCHAR(255),

  final_decision VARCHAR(50),

  high_frac FLOAT,
  is_alert BOOLEAN,
  is_suspicious BOOLEAN,

  max_p FLOAT,
  mean_p FLOAT,
  std_p FLOAT,

  risk_score FLOAT,
  time_bucket VARCHAR(100),

  dns_second_level_domain VARCHAR(255),
  severity VARCHAR(50),

  alert_count INT,
  alert_frac FLOAT,

  CONSTRAINT fk_dns_tunnel_events_plain
    FOREIGN KEY (plain_id) REFERENCES dns_tunneling_plain(plain_id)
    ON UPDATE CASCADE
    ON DELETE SET NULL,

  CONSTRAINT fk_dns_tunnel_events_doh
    FOREIGN KEY (doh_id) REFERENCES dns_tunneling_doh(doh_id)
    ON UPDATE CASCADE
    ON DELETE SET NULL

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dga_logs (
  plain_id BIGINT PRIMARY KEY
    COMMENT 'Raw Data. Maps directly back to the analyzed Plain Tunneling Query',

  timestamp DATETIME,
  level VARCHAR(50),
  host VARCHAR(255),
  domain VARCHAR(255),

  p_dga FLOAT,
  rule VARCHAR(255),
  reason VARCHAR(500),

  resolved_ips VARCHAR(1000),

  CONSTRAINT fk_dga_logs_plain
    FOREIGN KEY (plain_id) REFERENCES dns_tunneling_plain(plain_id)
    ON UPDATE CASCADE
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dga_events (
  event_id BIGINT PRIMARY KEY
    COMMENT 'Summarized Alerts (10s blocks within DGA logs)',

  window_start DATETIME,
  window_end DATETIME,

  host VARCHAR(255),
  severity VARCHAR(50),
  event_type VARCHAR(100),

  risk_score FLOAT,
  total_queries INT,
  unique_domains INT,

  max_p_dga FLOAT,

  top_domains VARCHAR(2000),
  reasons VARCHAR(2000),
  resolved_ips VARCHAR(2000)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dga_reputation (
  ip_address VARCHAR(45) PRIMARY KEY
    COMMENT 'External Intelligence on IPs identified in Events',

  timestamp DATETIME,
  country VARCHAR(100),

  vt_malicious INT,
  vt_harmless INT,
  vt_suspicious INT,
  vt_undetected INT,

  abuseipdb_confidence FLOAT,

  vt_report_url VARCHAR(2000),
  abuseipdb_report_url VARCHAR(2000)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS threat_intel (

  Post_Date DATETIME,
  Scan_Time DATETIME,

  Severity_Triage VARCHAR(50),
  Risk_Score FLOAT,
  Score_Driver VARCHAR(255),

  Sector VARCHAR(150),
  Sector_Confidence FLOAT,

  Location VARCHAR(150),
  Location_Confidence FLOAT,

  IoC_Summary VARCHAR(1000),
  URL VARCHAR(2000),
  Title VARCHAR(500),

  Full_IoC_JSON JSON

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

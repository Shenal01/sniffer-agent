# Exfiltrap Database Schema

This document outlines the tables and their corresponding schemas found in the exfiltrap database.

## Table: dga_events

| Column Name | Data Type | Column Type |
|---|---|---|
| event_id | bigint | bigint |
| event_type | varchar | varchar(100) |
| host | varchar | varchar(255) |
| max_p_dga | float | float |
| reasons | varchar | varchar(2000) |
| resolved_ips | varchar | varchar(2000) |
| risk_score | float | float |
| severity | varchar | varchar(50) |
| top_domains | varchar | varchar(2000) |
| total_queries | int | int |
| unique_domains | int | int |
| window_end | datetime | datetime |
| window_start | datetime | datetime |

## Table: dga_logs

| Column Name | Data Type | Column Type |
|---|---|---|
| domain | varchar | varchar(255) |
| host | varchar | varchar(255) |
| level | varchar | varchar(50) |
| p_dga | float | float |
| plain_id | bigint | bigint |
| reason | varchar | varchar(500) |
| resolved_ips | varchar | varchar(1000) |
| rule | varchar | varchar(255) |
| timestamp | datetime | datetime |

## Table: dga_reputation

| Column Name | Data Type | Column Type |
|---|---|---|
| abuseipdb_confidence | float | float |
| abuseipdb_report_url | varchar | varchar(2000) |
| country | varchar | varchar(100) |
| ip_address | varchar | varchar(45) |
| timestamp | datetime | datetime |
| vt_harmless | int | int |
| vt_malicious | int | int |
| vt_report_url | varchar | varchar(2000) |
| vt_suspicious | int | int |
| vt_undetected | int | int |

## Table: dns_abuse

| Column Name | Data Type | Column Type |
|---|---|---|
| average_packet_size | float | float |
| bwd_iat_mean | float | float |
| bwd_packet_length_mean | float | float |
| bwd_packets_per_sec | float | float |
| dns_amplification_factor | float | float |
| dns_any_query_ratio | float | float |
| dns_queries_per_second | float | float |
| dns_response_bytes | float | float |
| dns_response_inconsistency | float | float |
| dns_total_queries | float | float |
| dns_total_responses | float | float |
| dns_txt_query_ratio | float | float |
| doh_id | bigint | bigint |
| encrypted_payload_size_variance | float | float |
| flow_bytes_per_sec | float | float |
| flow_duration | float | float |
| flow_iat_max | float | float |
| flow_iat_mean | float | float |
| flow_iat_min | float | float |
| flow_iat_std | float | float |
| flow_id | bigint | bigint |
| flow_length_max | float | float |
| flow_length_min | float | float |
| flow_packets_per_sec | float | float |
| fwd_iat_mean | float | float |
| fwd_packet_length_mean | float | float |
| fwd_packets_per_sec | float | float |
| is_known_doh_server | tinyint | tinyint(1) |
| label | varchar | varchar(100) |
| large_packet_ratio | float | float |
| medium_packet_ratio | float | float |
| packet_size_std | float | float |
| port_53_traffic_ratio | float | float |
| protocol | varchar | varchar(50) |
| protocol_number | int | int |
| query_response_ratio | float | float |
| response_time_variance | float | float |
| small_packet_ratio | float | float |
| sni_entropy | float | float |
| total_bwd_bytes | float | float |
| total_bwd_packets | float | float |
| total_fwd_bytes | float | float |
| total_fwd_packets | float | float |

## Table: dns_all_doh

| Column Name | Data Type | Column Type |
|---|---|---|
| client_ip | varchar | varchar(45) |
| client_port | int | int |
| doh_id | bigint | bigint |
| features.behavioural_if.Duration | float | float |
| features.behavioural_if.FlowBytesReceived | float | float |
| features.behavioural_if.FlowBytesSent | float | float |
| features.behavioural_if.FlowReceivedRate | float | float |
| features.behavioural_if.FlowSentRate | float | float |
| features.behavioural_if.PacketLengthCoefficientofVariation | float | float |
| features.behavioural_if.PacketLengthMean | float | float |
| features.behavioural_if.PacketLengthMedian | float | float |
| features.behavioural_if.PacketLengthMode | float | float |
| features.behavioural_if.PacketLengthSkewFromMedian | float | float |
| features.behavioural_if.PacketLengthSkewFromMode | float | float |
| features.behavioural_if.PacketLengthStandardDeviation | float | float |
| features.behavioural_if.PacketLengthVariance | float | float |
| features.behavioural_if.PacketTimeCoefficientofVariation | float | float |
| features.behavioural_if.PacketTimeMean | float | float |
| features.behavioural_if.PacketTimeMedian | float | float |
| features.behavioural_if.PacketTimeMode | float | float |
| features.behavioural_if.PacketTimeSkewFromMedian | float | float |
| features.behavioural_if.PacketTimeSkewFromMode | float | float |
| features.behavioural_if.PacketTimeStandardDeviation | float | float |
| features.behavioural_if.PacketTimeVariance | float | float |
| features.behavioural_rf.Duration | float | float |
| features.behavioural_rf.FlowBytesReceived | float | float |
| features.behavioural_rf.FlowBytesSent | float | float |
| features.behavioural_rf.FlowReceivedRate | float | float |
| features.behavioural_rf.FlowSentRate | float | float |
| features.behavioural_rf.PacketLengthCoefficientofVariation | float | float |
| features.behavioural_rf.PacketLengthMean | float | float |
| features.behavioural_rf.PacketLengthMedian | float | float |
| features.behavioural_rf.PacketLengthMode | float | float |
| features.behavioural_rf.PacketLengthSkewFromMedian | float | float |
| features.behavioural_rf.PacketLengthSkewFromMode | float | float |
| features.behavioural_rf.PacketLengthStandardDeviation | float | float |
| features.behavioural_rf.PacketLengthVariance | float | float |
| features.behavioural_rf.PacketTimeCoefficientofVariation | float | float |
| features.behavioural_rf.PacketTimeMean | float | float |
| features.behavioural_rf.PacketTimeMedian | float | float |
| features.behavioural_rf.PacketTimeMode | float | float |
| features.behavioural_rf.PacketTimeSkewFromMedian | float | float |
| features.behavioural_rf.PacketTimeSkewFromMode | float | float |
| features.behavioural_rf.PacketTimeStandardDeviation | float | float |
| features.behavioural_rf.PacketTimeVariance | float | float |
| flow_features.Duration | float | float |
| flow_features.end_ts | datetime | datetime |
| flow_features.FlowBytesReceived | float | float |
| flow_features.FlowBytesSent | float | float |
| flow_features.FlowReceivedRate | float | float |
| flow_features.FlowSentRate | float | float |
| flow_features.PacketLengthCoefficientofVariation | float | float |
| flow_features.PacketLengthMean | float | float |
| flow_features.PacketLengthMedian | float | float |
| flow_features.PacketLengthMode | float | float |
| flow_features.PacketLengthSkewFromMedian | float | float |
| flow_features.PacketLengthSkewFromMode | float | float |
| flow_features.PacketLengthStandardDeviation | float | float |
| flow_features.PacketLengthVariance | float | float |
| flow_features.PacketTimeCoefficientofVariation | float | float |
| flow_features.PacketTimeMean | float | float |
| flow_features.PacketTimeMedian | float | float |
| flow_features.PacketTimeMode | float | float |
| flow_features.PacketTimeSkewFromMedian | float | float |
| flow_features.PacketTimeSkewFromMode | float | float |
| flow_features.PacketTimeStandardDeviation | float | float |
| flow_features.PacketTimeVariance | float | float |
| flow_features.ResponseTimeTimeCoefficientofVariation | float | float |
| flow_features.ResponseTimeTimeMean | float | float |
| flow_features.ResponseTimeTimeMedian | float | float |
| flow_features.ResponseTimeTimeMode | float | float |
| flow_features.ResponseTimeTimeSkewFromMedian | float | float |
| flow_features.ResponseTimeTimeSkewFromMode | float | float |
| flow_features.ResponseTimeTimeStandardDeviation | float | float |
| flow_features.ResponseTimeTimeVariance | float | float |
| flow_features.start_ts | datetime | datetime |
| raw | bigint | bigint |
| server_ip | varchar | varchar(45) |
| server_port | int | int |
| timestamp | datetime | datetime |
| traffic_type | varchar | varchar(50) |

## Table: dns_all_plain

| Column Name | Data Type | Column Type |
|---|---|---|
| dns_domain_name | varchar | varchar(255) |
| dns_domain_name_length | int | int |
| dns_second_level_domain | varchar | varchar(255) |
| dns_subdomain_name_length | int | int |
| dns_top_level_domain | varchar | varchar(50) |
| dst_ip | varchar | varchar(45) |
| dst_port | int | int |
| features.behavioural.character_entropy | float | float |
| features.behavioural.conv_freq_vowels_consonants | float | float |
| features.behavioural.dns_domain_name_length | int | int |
| features.behavioural.dns_subdomain_name_length | int | int |
| features.behavioural.hour | int | int |
| features.behavioural.is_night | tinyint | tinyint(1) |
| features.behavioural.max_continuous_alphabet_len | int | int |
| features.behavioural.max_continuous_consonants_len | int | int |
| features.behavioural.max_continuous_numeric_len | int | int |
| features.behavioural.max_continuous_same_alphabet_len | int | int |
| features.behavioural.numerical_percentage | float | float |
| features.behavioural.vowels_consonant_ratio | float | float |
| features.lexical.entropy | float | float |
| features.lexical.length | float | float |
| features.lexical.lex_compression_ratio | float | float |
| features.lexical.lex_first_label_has_digit | tinyint | tinyint(1) |
| features.lexical.lex_label_count | int | int |
| features.lexical.lex_len | int | int |
| features.lexical.lex_max_label_len | int | int |
| features.lexical.lex_tool_generated | tinyint | tinyint(1) |
| features.lexical.ratio_alpha | float | float |
| features.lexical.ratio_digit | float | float |
| features.lexical.ratio_hyphen | float | float |
| features.lexical.ratio_other | float | float |
| flow_id | bigint | bigint |
| plain_id | bigint | bigint |
| raw | bigint | bigint |
| src_ip | varchar | varchar(45) |
| src_port | int | int |
| timestamp | datetime | datetime |
| traffic_type | varchar | varchar(50) |

## Table: dns_tunnel_events

| Column Name | Data Type | Column Type |
|---|---|---|
| alert_count | int | int |
| alert_frac | float | float |
| client_ip | varchar | varchar(45) |
| component | varchar | varchar(100) |
| count | int | int |
| dns_second_level_domain | varchar | varchar(255) |
| doh_id | bigint | bigint |
| doh_key | varchar | varchar(255) |
| event_id | bigint | bigint |
| final_decision | varchar | varchar(50) |
| high_frac | float | float |
| is_alert | tinyint | tinyint(1) |
| is_suspicious | tinyint | tinyint(1) |
| max_p | float | float |
| mean_p | float | float |
| plain_id | bigint | bigint |
| risk_score | float | float |
| server_ip | varchar | varchar(45) |
| severity | varchar | varchar(50) |
| std_p | float | float |
| time_bucket | varchar | varchar(100) |

## Table: dns_tunneling_doh

| Column Name | Data Type | Column Type |
|---|---|---|
| component | varchar | varchar(100) |
| doh_id | bigint | bigint |
| features.behavioural_if.done | tinyint | tinyint(1) |
| features.behavioural_rf.done | tinyint | tinyint(1) |
| final_decision | varchar | varchar(50) |
| pipeline_status.classified_if | tinyint | tinyint(1) |
| pipeline_status.classified_rf | tinyint | tinyint(1) |
| pipeline_status.event_aggregated | tinyint | tinyint(1) |
| pipeline_status.features_extracted | tinyint | tinyint(1) |
| pipeline_status.features_extracted_if | tinyint | tinyint(1) |
| pipeline_status.features_extracted_rf | tinyint | tinyint(1) |
| pipeline_status.fusion_done | tinyint | tinyint(1) |
| pipeline_status.raw_ingested | tinyint | tinyint(1) |
| predictions.fused.label | varchar | varchar(100) |
| predictions.fused.reason | varchar | varchar(255) |
| predictions.fused.risk_score | float | float |
| predictions.fused.score | float | float |
| predictions.fused.severity | varchar | varchar(50) |
| predictions.if.label | varchar | varchar(100) |
| predictions.if.score | float | float |
| predictions.if.threshold | float | float |
| predictions.rf.label | varchar | varchar(100) |
| predictions.rf.score | float | float |
| predictions.rf.threshold | float | float |
| predictions.risk_score | float | float |
| predictions.severity | varchar | varchar(50) |
| time_bucket | varchar | varchar(100) |

## Table: dns_tunneling_plain

| Column Name | Data Type | Column Type |
|---|---|---|
| component | varchar | varchar(100) |
| features.behavioural.done | tinyint | tinyint(1) |
| features.lexical.done | tinyint | tinyint(1) |
| final_decision | varchar | varchar(50) |
| fusion_reason | varchar | varchar(255) |
| pipeline_status.classified_behavioural | tinyint | tinyint(1) |
| pipeline_status.classified_lexical | tinyint | tinyint(1) |
| pipeline_status.event_aggregated | tinyint | tinyint(1) |
| pipeline_status.features_extracted | tinyint | tinyint(1) |
| pipeline_status.fusion_done | tinyint | tinyint(1) |
| pipeline_status.raw_ingested | tinyint | tinyint(1) |
| plain_id | bigint | bigint |
| predictions.behavioural | varchar | varchar(100) |
| predictions.fused | varchar | varchar(100) |
| predictions.lexical | varchar | varchar(100) |
| predictions.risk_score | float | float |
| predictions.severity | varchar | varchar(50) |
| time_bucket | varchar | varchar(100) |

## Table: threat_intel

| Column Name | Data Type | Column Type |
|---|---|---|
| Full_IoC_JSON | json | json |
| IoC_Summary | varchar | varchar(1000) |
| Location | varchar | varchar(150) |
| Location_Confidence | float | float |
| Post_Date | datetime | datetime |
| Risk_Score | float | float |
| Scan_Time | datetime | datetime |
| Score_Driver | varchar | varchar(255) |
| Sector | varchar | varchar(150) |
| Sector_Confidence | float | float |
| Severity_Triage | varchar | varchar(50) |
| Title | varchar | varchar(500) |
| URL | varchar | varchar(2000) |


-- migrate:up
CREATE TABLE requests (
    timestamp DateTime64(3) DEFAULT now64(3),
    request_id UUID DEFAULT generateUUIDv4(),

    -- proxy metadata
    proxy_string String,
    proxy_domain Nullable(String),

    -- ip features
    ip_address IPv4,
    ip_total_length UInt16,
    ip_header_length UInt8,
    ip_dscp UInt8,
    ip_ecn UInt8,
    ip_id_present Bool,
    ip_initial_ttl UInt8,
    ip_hops_count UInt8,
    ip_reserved_flag Bool,
    ip_dont_fragment Bool,
    ip_more_fragments Bool,
    ip_fragment_offset UInt16,
    ip_options_count UInt32,

    -- tcp features
    tcp_data_offset UInt8,
    tcp_reserved UInt8,
    tcp_flags UInt8,
    tcp_window_size UInt16,
    tcp_window_scaling UInt8,
    tcp_scaled_window_size UInt32,
    tcp_window_mss_multiple UInt16,
    tcp_urgent_ptr UInt16,
    tcp_options_count UInt32,
    tcp_options_order LowCardinality(String),
    tcp_max_segment_size UInt16,
    tcp_mtu_size UInt16,
    tcp_timestamp Bool,
    tcp_timestamp_echo_reply Bool,
    tcp_selective_ack Bool,

    -- reputation/geo
    rep_as_number LowCardinality(String),
    rep_as_description String,
    rep_as_name LowCardinality(String),
    rep_as_org LowCardinality(String),
    rep_as_isp LowCardinality(String),
    rep_continent_code LowCardinality(String),
    rep_country_code LowCardinality(String),
    rep_region LowCardinality(String),
    rep_city LowCardinality(String),
    rep_district String,
    rep_zip_code String,
    rep_timezone LowCardinality(String),
    rep_utc_offset Int64,
    rep_lat Float64,
    rep_lon Float64,
    rep_is_proxy Bool,
    rep_is_mobile Bool,
    rep_is_hosting Bool
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (ip_address, timestamp);

-- migrate:down
DROP TABLE requests;
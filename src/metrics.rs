use prometheus::{
    Encoder, IntCounter, IntGauge, TextEncoder, gather, register_int_counter, register_int_gauge,
};

lazy_static::lazy_static! {
    pub static ref TOTAL_DOWNTIME: IntCounter = register_int_counter!("total_downtime_seconds", "Total downtime in seconds").unwrap();
    pub static ref TOTAL_UPTIME: IntCounter = register_int_counter!("total_uptime_seconds", "Total uptime in seconds").unwrap();
    pub static ref TOTAL_OUTAGES: IntCounter = register_int_counter!("total_outages", "Total number of outages").unwrap();
    pub static ref INTERNET_STATUS: IntGauge = register_int_gauge!("internet_status", "Current internet status (1 for up, 0 for down)").unwrap();
}

// Function to update the total downtime
pub fn increment_downtime(seconds: u64) {
    TOTAL_DOWNTIME.inc_by(seconds);
}

// Function to update the total outages
pub fn increment_outages() {
    TOTAL_OUTAGES.inc();
}

// Function to expose metrics
pub async fn metrics_handler() -> Result<impl warp::Reply, warp::Rejection> {
    let encoder = TextEncoder::new();
    let metric_families = gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    Ok(warp::reply::with_header(
        String::from_utf8(buffer).unwrap(),
        "content-type",
        encoder.format_type(),
    ))
}

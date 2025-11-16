use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub ntfy_url: String,
    pub ntfy_title: String,
    pub ntfy_token: String,
    pub ntfy_tag: Option<String>,
    pub ntfy_priority: Option<String>,
    pub check_urls: Vec<String>,
    pub check_interval: Option<u64>,
    pub check_timeout: Option<u64>,
    pub debug: Option<bool>,
    pub prometheus_port: Option<u16>,
}

impl Config {
    pub fn ntfy_tag(&self) -> &str {
        self.ntfy_tag.as_deref().unwrap_or("warning")
    }

    pub fn ntfy_priority(&self) -> &str {
        self.ntfy_priority.as_deref().unwrap_or("default")
    }

    pub fn check_interval(&self) -> u64 {
        self.check_interval.unwrap_or(5)
    }

    pub fn check_timeout(&self) -> u64 {
        self.check_timeout.unwrap_or(60)
    }

    pub fn debug(&self) -> bool {
        self.debug.unwrap_or(false)
    }

    pub fn prometheus_port(&self) -> u16 {
        self.prometheus_port.unwrap_or(3030)
    }
}

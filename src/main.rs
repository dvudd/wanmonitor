use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, Duration};
use std::{env, fs};
use chrono::{DateTime, Local};
use config::Config;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use warp::Filter;
mod config;
mod metrics;

/// Reads the path to the configuration file.
/// * Throws an error if the config does not exist.
fn get_config_path() -> Result<String, String> {
    if let Ok(exe_path) = env::current_exe() && let Some(exe_dir) = exe_path.parent() {
            let config_path = exe_dir.join("wanmonitor.conf");
            if config_path.exists() {
                return Ok(config_path.to_string_lossy().to_string());
            } else {
                return Err(format!("Config file '{}' does not exist.", config_path.display()));
            }
    }
    Err("Failed to determine the executable path.".to_string())
}

/// Loads configuration from a TOML file.
/// * Throws an error if the config file is not readable.
/// * Throws an error if the config file has syntax error. 
fn load_config() -> Config {
    // Read config path
    let config_path = get_config_path().unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    // Debug message
    log::debug!("Loading config from: {}", config_path);
    
    // Read config file
    let config_str = fs::read_to_string(&config_path)
        .unwrap_or_else(|_e_| {
            eprintln!("Error: Cannot read config file '{}'", config_path);
            eprintln!("Please ensure the file exists and is readable.");
            std::process::exit(1);
        });
    
    // Parse TOML
    toml::from_str(&config_str)
        .unwrap_or_else(|_e_| {
            eprintln!("Error: Failed to parse TOML config file '{}'", config_path);
            eprintln!("Please check the syntax of your configuration file.");
            std::process::exit(1);
        })
}

/// Sends a notification message to an ntfy server.
///
/// # Arguments
/// * `url` - The ntfy server URL to send the notification to
/// * `title` - The title of the notification
/// * `token` - The authentication token for the ntfy server
/// * `tags` - Tags to categorize the notification
/// * `message` - The body of the notification message
/// * `priority` - The priority level of the notification
///
/// # Returns
/// * `Ok(())` if the notification was sent successfully
/// * `Err` if there was an error sending the notification
fn send_ntfy(
    url: &str,
    title: &str,
    token: &str,
    tags: &str,
    message: &str,
    priority: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let auth_header = format!("Bearer {}", token);

    let res = client
        .post(url)
        .header(AUTHORIZATION, HeaderValue::from_str(&auth_header)?)
        .header("Title", title)
        .header("Tags", tags)
        .header("Priority", priority)
        .body(message.to_string())
        .send()?;

    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("Failed to send notification: HTTP {}", res.status()).into())
    }
}

/// Checks if internet connectivity is available by making an HTTP GET request to the specified URL.
///
/// # Arguments
/// * `client` - The HTTP client to use for the request
/// * `url` - The URL to test connectivity against
///
/// # Returns
/// * `true` if the HTTP request succeeds with a successful status code
/// * `false` if the request fails, times out, or returns an error status
fn is_internet_up(client: &reqwest::blocking::Client, url: &str) -> bool {
    client.get(url).send().map(|r| r.status().is_success()).unwrap_or(false)
}

/// Main function that monitors internet connectivity and sends notifications via ntfy.
///
/// This function:
/// 1. Loads configuration from environment variables and .env file
/// 2. Sets up logging based on DEBUG environment variable
/// 3. Sends a test notification if in debug mode
/// 4. Sets up graceful shutdown handling (Ctrl+C)
/// 5. Continuously monitors internet connectivity by checking configured URLs
/// 6. Sends notifications when internet goes down or comes back up
/// 7. Includes downtime duration in restoration notifications
fn main() {
    // Load configuration from TOML file
    let config = load_config();

    // Initialize logger
    let log_level = if config.debug() { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    // Set up graceful shutdown flag
    let running = Arc::new(AtomicBool::new(true));

    // Start the metrics server in a separate thread
    let metrics_route = warp::path("metrics").and_then(metrics::metrics_handler);
    let metrics_port = config.prometheus_port();
    let running_metrics = running.clone();
    thread::spawn(move || {
      let running_inner = running_metrics.clone();
      let rt = tokio::runtime::Runtime::new().unwrap();
      rt.block_on(async {
          let (_addr, server) = warp::serve(metrics_route)
              .bind_with_graceful_shutdown(([127, 0, 0, 1], metrics_port), async move {
                  // Wait until running becomes false
                  while running_inner.load(Ordering::SeqCst) {
                      tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                  }
              });
          server.await;
      });
    });

    // Create HTTP client for connectivity checks
    let http_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .expect("Failed to create HTTP client");

    // Set mutable variables
    let mut was_down = false;
    let mut down_since: Option<SystemTime> = None;

    // Log entry to indicate program start.
    log::info!("Starting...");

    // Send a test notification to verify ntfy setup
    if config.debug() {
        match send_ntfy(&config.ntfy_url, &config.ntfy_title, &config.ntfy_token, config.ntfy_tag(), "wanmonitor started: ntfy test message", config.ntfy_priority()) {
            Ok(_) => log::info!("Successfully sent test notification to ntfy."),
            Err(e) => log::error!("Failed to send test notification to ntfy: {}", e),
        }
    }

    // Set up graceful shutdown handler
    let running_ctrlc = running.clone();
    let url_clone = config.ntfy_url.clone();
    let title_clone = config.ntfy_title.clone();
    let token_clone = config.ntfy_token.clone();
    let tags_clone = config.ntfy_tag().to_string();
    let priority_clone = config.ntfy_priority().to_string();
    let debug_clone = config.debug();
    ctrlc::set_handler(move || {
        log::info!("Shutdown signal received. Exiting...");
        if debug_clone && let Err(e) = send_ntfy(&url_clone, &title_clone, &token_clone, &tags_clone, "wanmonitor shutting down", &priority_clone) {
                log::error!("Failed to send shutdown notification: {}", e);
        }
        running_ctrlc.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    // Main Loop
    while running.load(Ordering::SeqCst) {
        // Check connection
            let internet_up = config.check_urls.iter().any(|url| is_internet_up(&http_client, url));
            if internet_up {
            // If the connection was down before but is now up, send the total outage time
            metrics::INTERNET_STATUS.set(1);
            metrics::TOTAL_UPTIME.inc_by(config.check_interval());
            if was_down {
                // Internet just came back up
                if let Some(start) = down_since {
                    let end = SystemTime::now();
                    if let Ok(elapsed) = end.duration_since(start) {
                        // Format start time as local time string
                        let start_datetime: DateTime<Local> = DateTime::<Local>::from(start);
                        let start_str = start_datetime.format("%Y-%m-%d %H:%M:%S").to_string();
                        // Format duration as HH:MM:SS
                        let total_secs = elapsed.as_secs();
                        let hours = total_secs / 3600;
                        let mins = (total_secs % 3600) / 60;
                        let secs = total_secs % 60;
                        let duration_str = format!("{:02}:{:02}:{:02}", hours, mins, secs);
                        // Set the notification message
                        let msg = format!(
                            "Internet connection has been restored! The outage started at {} and lasted for {}",
                            start_str, duration_str
                        );
                        // Reduce unnecessary notifications
                        if total_secs > config.check_timeout() {
                            if let Err(e) = send_ntfy(&config.ntfy_url, &config.ntfy_title, &config.ntfy_token, config.ntfy_tag(), &msg, config.ntfy_priority()) {
                                log::error!("Failed to send restoration notification: {}", e);
                            }
                            log::info!("{}", msg)
                        }
                    }
                }
                was_down = false;
                down_since = None;
            } else {
                // Add successful message to debug log
                log::debug!("Successful connection established");
            }
        } else {
            // If the connection goes down, start logging the time and send a notification
            metrics::INTERNET_STATUS.set(0);
            metrics::increment_downtime(config.check_interval()); 
            if !was_down {
                // Internet just went down
                down_since = Some(SystemTime::now());
                let msg = format!(
                    "Internet outage detected at {}",
                    chrono::DateTime::<chrono::Local>::from(SystemTime::now()).format("%Y-%m-%d %H:%M:%S")
                );

                // Increment the outages counter
                metrics::increment_outages();

                if let Err(e) = send_ntfy(&config.ntfy_url, &config.ntfy_title, &config.ntfy_token, config.ntfy_tag(), &msg, config.ntfy_priority()) {
                    log::error!("Failed to send outage notification: {}", e);
                }
                log::warn!("{}", msg);
                was_down = true;
            }
        }
        thread::sleep(Duration::from_secs(config.check_interval()));
    }
}

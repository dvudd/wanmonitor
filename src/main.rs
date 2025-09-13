use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use std::thread;
use std::time::{SystemTime, Duration};
use chrono::{DateTime, Local};
use std::env;
use dotenv::dotenv;

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
    dotenv().ok();
    // Initialize logger
    let debug = env::var("DEBUG").unwrap_or_else(|_| "false".to_string());
    let log_level = if debug.to_lowercase() == "true" { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    // Load .env file, check that the necessary variables exists
    let url = env::var("NTFY_URL").expect("NTFY_URL must be set");
    let title = env::var("NTFY_TITLE").expect("NTFY_TITLE must be set");
    let token = env::var("NTFY_TOKEN").expect("NTFY_TOKEN must be set");
    let tags = env::var("NTFY_TAG").unwrap_or_else(|_| "warning".to_string());
    let priority = env::var("NTFY_PRIORITY").unwrap_or_else(|_| "default".to_string());
    let urls = env::var("CHECK_URLS")
        .expect("CHECK_URLS must be set")
        .split(',')
        .map(|s| s.trim().to_string())
        .collect::<Vec<String>>();
    let interval: u64 = env::var("CHECK_INTERVAL")
    .unwrap_or_else(|_| "5".to_string())
    .parse()
    .expect("CHECK_INTERVAL must be a valid integer");
    let timeout: u64 = env::var("CHECK_TIMEOUT")
        .unwrap_or_else(|_| "60".to_string())
        .parse()
        .expect("CHECK_TIMEOUT must be a valid integer");

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
    if debug.to_lowercase() == "true" {
        match send_ntfy(&url, &title, &token, &tags, "wanmonitor started: ntfy test message", &priority) {
            Ok(_) => log::info!("Successfully sent test notification to ntfy."),
            Err(e) => log::error!("Failed to send test notification to ntfy: {}", e),
        }
    }

    // Set up graceful shutdown flag
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let url_clone = url.clone();
    let title_clone = title.clone();
    let token_clone = token.clone();
    let tags_clone = tags.clone();
    let priority_clone = priority.clone();
    ctrlc::set_handler(move || {
        log::info!("Shutdown signal received. Exiting...");
        if debug.to_lowercase() == "true" {
            let _ = send_ntfy(&url_clone, &title_clone, &token_clone, &tags_clone, "wanmonitor shutting down", &priority_clone);
        }
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    // Main Loop
    while running.load(Ordering::SeqCst) {
        // Check connection
            let internet_up = urls.iter().any(|url| is_internet_up(&http_client, url));
            if internet_up {
            // If the connection was down before but is now up, send the total outage time
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
                        if total_secs > timeout {
                            let _ = send_ntfy(&url, &title, &token, &tags, &msg, &priority);
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
            if !was_down {
                // Internet just went down
                down_since = Some(SystemTime::now());
                let msg = format!(
                    "Internet outage detected at {}",
                    chrono::DateTime::<chrono::Local>::from(SystemTime::now()).format("%Y-%m-%d %H:%M:%S")
                );
                let _ = send_ntfy(&url, &title, &token, &tags, &msg, &priority);
                log::warn!("{}", msg);
                was_down = true;
            }
        }
        thread::sleep(Duration::from_secs(interval));
    }
}
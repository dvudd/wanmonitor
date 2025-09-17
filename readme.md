# Wan monitor

This will monitor your WAN connection and send a notification via NTFY when it goes down/up

To build:
```rust
cargo build --relase
```

### Configuration
The configuration file has to be in the same folder as the binary.
Example:
```toml
ntfy_url = "https://ntfy.sh/your-topic"
ntfy_title = "WAN Monitor"
ntfy_token = "your-ntfy-token-here"
ntfy_tag = "warning"
ntfy_priority = "default"
check_urls = ["https://1.1.1.1", "https://8.8.8.8", "https://www.google.com"]
check_interval = 5
check_timeout = 60
debug = false
```

//! Shared HTTP client with connect and request timeouts.

use std::sync::OnceLock;
use std::time::Duration;

/// Process-wide client: 10 s connect timeout, 30 s total request timeout.
/// A per-request `.timeout(..)` overrides the total timeout.
pub fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("static reqwest config")
    })
}

#[cfg(test)]
mod tests {
    use super::http_client;

    #[test]
    fn http_client_is_singleton() {
        assert!(std::ptr::eq(http_client(), http_client()));
    }
}

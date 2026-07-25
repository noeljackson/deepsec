use reqwest::header::AUTHORIZATION;
use reqwest::Client;

async fn configured_proxy(client: Client, upstream_credential: &str) {
    let _ = client
        .get("https://api.example.test/profile")
        .header(AUTHORIZATION, upstream_credential)
        .send()
        .await;
}

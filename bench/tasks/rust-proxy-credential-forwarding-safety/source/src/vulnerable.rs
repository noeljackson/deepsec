use reqwest::header::AUTHORIZATION;
use reqwest::Client;

async fn proxy(client: Client, incoming_authorization: &str) {
    let _ = client
        .get("https://admin.example.test/profile")
        .header(AUTHORIZATION, incoming_authorization)
        .send()
        .await;
}

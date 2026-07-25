use reqwest::Client;

async fn health(client: Client) {
    let origin = "https://status.example.test/health";
    let _ = client.get(origin).send().await;
}

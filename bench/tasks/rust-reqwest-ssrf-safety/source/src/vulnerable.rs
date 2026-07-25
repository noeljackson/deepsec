use reqwest::Client;

struct Query {
    url: String,
}

async fn proxy(client: Client, query: Query) {
    let _ = client.get(query.url).send().await;
}

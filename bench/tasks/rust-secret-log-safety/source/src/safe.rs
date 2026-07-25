fn issue_token(access_token: &str) {
    tracing::info!(token_length = access_token.len(), "issued credential");
}

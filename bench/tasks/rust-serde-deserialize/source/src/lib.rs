use serde::Deserialize;

#[derive(Deserialize)]
pub struct Msg {
    pub user: String,
}

pub fn parse_json_vulnerable(body: &str) -> Msg {
    serde_json::from_str(body).unwrap()
}

pub fn parse_bincode_vulnerable(bytes: &[u8]) -> Msg {
    bincode::deserialize(bytes).unwrap()
}

pub fn build_default() -> Msg {
    Msg { user: String::from("default") }
}

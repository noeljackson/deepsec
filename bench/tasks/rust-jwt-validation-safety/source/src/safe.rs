use jsonwebtoken::{Algorithm, Validation};

fn strict_policy() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.set_issuer(&["https://issuer.example.test"]);
    validation.set_audience(&["broker"]);
    validation
}

fn asymmetric_policy() -> Validation {
    Validation::new(Algorithm::RS256)
}

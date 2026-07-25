use jsonwebtoken::{Algorithm, Validation};

fn weak_expiry_policy() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    // The service accepts expired bearer tokens.
    validation.validate_exp = false;
    validation
}

fn unsigned_policy() -> Validation {
    Validation::new(Algorithm::None)
}

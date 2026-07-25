// VULN: secrets-exposure — Hardcoded API keys and secrets

export const config = {
  stripe: {
    secretKey: "sk-live-51H3bK2eZvKYlo2C0asdf1234567890abcdefgh", // gitleaks:allow -- synthetic planted-vulnerability fixture, not a valid credential
    publishableKey: "pk_live_example",
  },
  database: {
    password: "super_secret_db_password_123",
    connectionString: "postgres://admin:password123@db.example.com/prod",
  },
  jwt: {
    secret: "my-jwt-secret-key-do-not-share",
  },
  aws: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  },
};

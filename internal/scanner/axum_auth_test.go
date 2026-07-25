package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAxumMutationRoutesWithoutAuthFollowsHandler(t *testing.T) {
	content := `
async fn create_item(payload: String) {}
async fn update_item(AuthContext(_auth): AuthContext, payload: String) {}
async fn delete_item(payload: String) { require_authorized(&payload).await; }
fn router() {
  Router::new()
    .route("/items", post(create_item))
    .route("/items/:id", put(update_item))
    .route("/items/:id", delete(delete_item))
}`
	candidates := axumMutationRoutesWithoutAuth(content)
	require.Len(t, candidates, 1)
	require.Equal(t, "rust-axum-no-auth-extractor", candidates[0].VulnSlug)
	require.Contains(t, candidates[0].Snippet, "create_item")
}

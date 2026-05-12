package processor

import promptdata "github.com/noeljackson/deepsec/internal/processor/prompts"

// HighlightForTag returns the framework-specific threat context for a
// detected-tech tag, or empty string for unknown tags.
func HighlightForTag(tag string) string {
	return promptdata.HighlightForTag(tag)
}

// NoteForSlug returns the per-matcher reasoning hint, or empty string.
func NoteForSlug(slug string) string {
	return promptdata.NoteForSlug(slug)
}

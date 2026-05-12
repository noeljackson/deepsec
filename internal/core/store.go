package core

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// EnsureProject creates `data/<projectId>/project.json` if it doesn't
// already exist, and returns the resulting ProjectConfig. Idempotent:
// repeated calls return the same value.
func (r DataRoot) EnsureProject(projectID, rootPath, githubURL string) (*ProjectConfig, error) {
	p, err := r.ProjectConfigPath(projectID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}
	if existing, err := readJSON[ProjectConfig](p); err != nil {
		return nil, err
	} else if existing != nil {
		return existing, nil
	}
	cfg := &ProjectConfig{
		ProjectID: projectID,
		RootPath:  rootPath,
		CreatedAt: NowISO(),
		GithubURL: githubURL,
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, body, 0o644); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ReadProjectConfig returns nil if the project's config.json doesn't exist.
func (r DataRoot) ReadProjectConfig(projectID string) (*ProjectConfig, error) {
	p, err := r.ProjectConfigPath(projectID)
	if err != nil {
		return nil, err
	}
	return readJSON[ProjectConfig](p)
}

// WriteProjectConfig persists the given config.
func (r DataRoot) WriteProjectConfig(cfg *ProjectConfig) error {
	p, err := r.ProjectConfigPath(cfg.ProjectID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return writeJSON(p, cfg)
}

// ReadFileRecord returns nil if no record exists for filePath.
func (r DataRoot) ReadFileRecord(projectID, filePath string) (*FileRecord, error) {
	p, err := r.FileRecordPath(projectID, filePath)
	if err != nil {
		return nil, err
	}
	return readJSON[FileRecord](p)
}

func (r DataRoot) WriteFileRecord(rec *FileRecord) error {
	p, err := r.FileRecordPath(rec.ProjectID, rec.FilePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return writeJSON(p, rec)
}

// LoadAllFileRecords walks `data/<projectId>/files/` and returns every
// FileRecord found. Skips malformed JSON silently.
func (r DataRoot) LoadAllFileRecords(projectID string) ([]*FileRecord, error) {
	dir, err := r.FilesDir(projectID)
	if err != nil {
		return nil, err
	}
	out := make([]*FileRecord, 0)
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) {
				return fs.SkipDir
			}
			return walkErr
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		rec, err := readJSON[FileRecord](path)
		if err != nil || rec == nil {
			return nil
		}
		out = append(out, rec)
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return out, nil
}

// --- internal helpers ---

func readJSON[T any](path string) (*T, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func writeJSON(path string, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DataRoot is the on-disk mirror root. Defaults to "data" relative to
// the working directory; overridable via DEEPSEC_DATA_ROOT or
// `data_dir` in the TOML config.
type DataRoot struct {
	Path string
}

// DataRootFromEnv reads DEEPSEC_DATA_ROOT or falls back to "data".
func DataRootFromEnv() DataRoot {
	if v := os.Getenv("DEEPSEC_DATA_ROOT"); v != "" {
		return DataRoot{Path: v}
	}
	return DataRoot{Path: "data"}
}

// DataRootFromPath wraps an explicit path (used by tests + --data-dir).
func DataRootFromPath(p string) DataRoot {
	return DataRoot{Path: p}
}

// AssertSafeSegment rejects empty, '.', '..', absolute paths, null
// bytes, and any path separator. Used at every entry point that joins
// user-supplied segments onto a per-project mirror so a `../`-laced
// projectId/runId can't escape the mirror or clobber a sibling
// project's files.
func AssertSafeSegment(name, label string) error {
	if name == "" {
		return fmt.Errorf("invalid %s: must be a non-empty string", label)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid %s: %q", label, name)
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("invalid %s: contains null byte", label)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid %s: contains path separator", label)
	}
	if filepath.IsAbs(name) {
		return fmt.Errorf("invalid %s: must not be absolute", label)
	}
	return nil
}

// AssertSafeFilePath rejects null bytes, backslashes, absolute paths,
// and `..` / `.` / empty segments. Allows forward-slash separators so
// nested file paths can be stored as segments under `files/`.
func AssertSafeFilePath(p string) error {
	if p == "" {
		return errors.New("invalid filePath: must be a non-empty string")
	}
	if strings.ContainsRune(p, 0) {
		return errors.New("invalid filePath: contains null byte")
	}
	if strings.ContainsRune(p, '\\') {
		return errors.New("invalid filePath: contains backslash")
	}
	if filepath.IsAbs(p) {
		return errors.New("invalid filePath: must not be absolute")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("invalid filePath: contains %q segment", seg)
		}
	}
	return nil
}

func (r DataRoot) DataDir(projectID string) (string, error) {
	if err := AssertSafeSegment(projectID, "projectId"); err != nil {
		return "", err
	}
	return filepath.Join(r.Path, projectID), nil
}

func (r DataRoot) ProjectConfigPath(projectID string) (string, error) {
	d, err := r.DataDir(projectID)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "project.json"), nil
}

func (r DataRoot) FilesDir(projectID string) (string, error) {
	d, err := r.DataDir(projectID)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "files"), nil
}

// FileRecordPath returns the on-disk JSON path for a FileRecord.
// `filePath` is the project-relative source path with forward slashes;
// `.json` is appended to the leaf segment.
func (r DataRoot) FileRecordPath(projectID, filePath string) (string, error) {
	if err := AssertSafeFilePath(filePath); err != nil {
		return "", err
	}
	files, err := r.FilesDir(projectID)
	if err != nil {
		return "", err
	}
	// `.json` is appended after the extension so `src/x.ts` becomes
	// `files/src/x.ts.json`.
	parts := strings.Split(filePath, "/")
	parts[len(parts)-1] = parts[len(parts)-1] + ".json"
	return filepath.Join(append([]string{files}, parts...)...), nil
}

func (r DataRoot) RunsDir(projectID string) (string, error) {
	d, err := r.DataDir(projectID)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "runs"), nil
}

func (r DataRoot) RunMetaPath(projectID, runID string) (string, error) {
	if err := AssertSafeSegment(runID, "runId"); err != nil {
		return "", err
	}
	d, err := r.RunsDir(projectID)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, runID+".json"), nil
}

func (r DataRoot) ReportsDir(projectID string) (string, error) {
	d, err := r.DataDir(projectID)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "reports"), nil
}

func reportName(prefix, runID, ext string) (string, error) {
	if runID == "" {
		return prefix + "." + ext, nil
	}
	if err := AssertSafeSegment(runID, "runId"); err != nil {
		return "", err
	}
	return prefix + "-" + runID + "." + ext, nil
}

func (r DataRoot) ReportJSONPath(projectID, runID string) (string, error) {
	d, err := r.ReportsDir(projectID)
	if err != nil {
		return "", err
	}
	name, err := reportName("report", runID, "json")
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name), nil
}

func (r DataRoot) ReportMDPath(projectID, runID string) (string, error) {
	d, err := r.ReportsDir(projectID)
	if err != nil {
		return "", err
	}
	name, err := reportName("report", runID, "md")
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name), nil
}

func (r DataRoot) ReportCSVPath(projectID, runID string) (string, error) {
	d, err := r.ReportsDir(projectID)
	if err != nil {
		return "", err
	}
	name, err := reportName("report", runID, "csv")
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name), nil
}

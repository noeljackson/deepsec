package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noeljackson/deepsec/internal/core"
)

// DetectedTech is the cached result of scanning a project root for
// framework / language markers.
type DetectedTech struct {
	Tags       []string `json:"tags"`
	Sentinels  []string `json:"sentinels"`
	DetectedAt string   `json:"detectedAt"`
	RootPath   string   `json:"rootPath"`
}

const (
	maxNestedWorkspaceManifests = 64
	maxNestedWorkspaceDepth     = 6
)

// Detect runs the manifest-reading detector chain. Fast; called once
// per scan.
func Detect(root string) DetectedTech {
	tags := map[string]struct{}{}
	sentinels := []string{}
	read := func(name string) (string, bool) {
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			return "", false
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", false
		}
		return string(b), true
	}

	if pkg, ok := read("package.json"); ok {
		sentinels = append(sentinels, "package.json")
		tags["node"] = struct{}{}
		if strings.Contains(pkg, "\"typescript\"") {
			tags["typescript"] = struct{}{}
		}
		if _, err := os.Stat(filepath.Join(root, "tsconfig.json")); err == nil {
			tags["typescript"] = struct{}{}
		}
		check := func(tag, needle string) {
			if strings.Contains(pkg, needle) {
				tags[tag] = struct{}{}
			}
		}
		check("nextjs", "\"next\"")
		check("nextjs", "\"@vercel/next\"")
		check("react", "\"react\"")
		check("express", "\"express\"")
		check("fastify", "\"fastify\"")
		check("nestjs", "\"@nestjs/core\"")
		check("koa", "\"koa\"")
		check("hapi", "\"@hapi/hapi\"")
		check("hono", "\"hono\"")
		check("remix", "\"remix\"")
		check("remix", "\"@remix-run/")
		check("sveltekit", "\"@sveltejs/kit\"")
		check("svelte", "\"svelte\"")
		check("svelte", "\"@sveltejs/")
		check("astro", "\"astro\"")
		check("solidstart", "\"@solidjs/start\"")
		check("nuxt", "\"nuxt\"")
		check("graphql", "\"graphql\"")
		check("graphql", "\"@apollo/server\"")
	}

	if anyOf(root, "requirements.txt", "pyproject.toml", "setup.py") {
		sentinels = append(sentinels, "python")
		tags["python"] = struct{}{}
		body := concatRead(root, "requirements.txt", "pyproject.toml", "setup.py")
		lc := strings.ToLower(body)
		if strings.Contains(lc, "django") {
			tags["django"] = struct{}{}
		}
		if strings.Contains(lc, "fastapi") {
			tags["fastapi"] = struct{}{}
		}
		if strings.Contains(lc, "flask") {
			tags["flask"] = struct{}{}
		}
		if strings.Contains(lc, "starlette") {
			tags["starlette"] = struct{}{}
		}
	}

	if gem, ok := read("Gemfile"); ok {
		sentinels = append(sentinels, "Gemfile")
		tags["ruby"] = struct{}{}
		if strings.Contains(gem, "'rails'") || strings.Contains(gem, "\"rails\"") {
			tags["rails"] = struct{}{}
		}
		if strings.Contains(gem, "'sinatra'") {
			tags["sinatra"] = struct{}{}
		}
	}

	if gomod, ok := read("go.mod"); ok {
		sentinels = append(sentinels, "go.mod")
		tags["go"] = struct{}{}
		if strings.Contains(gomod, "gin-gonic/gin") {
			tags["gin"] = struct{}{}
		}
		if strings.Contains(gomod, "labstack/echo") {
			tags["echo"] = struct{}{}
		}
		if strings.Contains(gomod, "gofiber/fiber") {
			tags["fiber"] = struct{}{}
		}
		if strings.Contains(gomod, "go-chi/chi") {
			tags["chi"] = struct{}{}
		}
	}

	if cargo, ok := read("Cargo.toml"); ok {
		sentinels = append(sentinels, "Cargo.toml")
		tags["rust"] = struct{}{}
		if strings.Contains(cargo, "axum") {
			tags["axum"] = struct{}{}
		}
		if strings.Contains(cargo, "actix-web") {
			tags["actix"] = struct{}{}
		}
		if strings.Contains(cargo, "rocket") {
			tags["rocket"] = struct{}{}
		}
		if strings.Contains(cargo, "warp") {
			tags["warp"] = struct{}{}
		}
	}

	if _, ok := read("composer.json"); ok {
		sentinels = append(sentinels, "composer.json")
		tags["php"] = struct{}{}
	}
	if anyOf(root, "pom.xml", "build.gradle", "build.gradle.kts") {
		tags["jvm"] = struct{}{}
	}
	if _, ok := read("Dockerfile"); ok {
		sentinels = append(sentinels, "Dockerfile")
		tags["docker"] = struct{}{}
	}
	if isDir(filepath.Join(root, ".github/workflows")) {
		sentinels = append(sentinels, ".github/workflows")
		tags["github-actions"] = struct{}{}
	}

	// Monorepos commonly place the browser/UI application under ui/, apps/,
	// or packages/. WalkProject already applies project ignore rules and skips
	// vendor/build trees. Bound manifests and depth so discovery stays cheap and
	// cannot be inflated by a hostile checkout.
	if files, err := WalkProject(root); err == nil {
		manifestCount := 0
		for _, rel := range files {
			dir := filepath.ToSlash(filepath.Dir(rel))
			if dir == "." || workspaceDepth(rel) > maxNestedWorkspaceDepth {
				continue
			}
			name := filepath.Base(rel)
			if name != "package.json" && name != "Cargo.toml" && name != "tsconfig.json" && name != "Chart.yaml" {
				if strings.EqualFold(filepath.Ext(rel), ".svelte") {
					tags["svelte"] = struct{}{}
					tags["typescript"] = struct{}{}
				}
				continue
			}
			manifestCount++
			if manifestCount > maxNestedWorkspaceManifests {
				break
			}
			body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				continue
			}
			sentinels = append(sentinels, rel)
			switch name {
			case "package.json":
				detectNodePackage(tags, string(body))
			case "Cargo.toml":
				detectCargoPackage(tags, string(body))
			case "tsconfig.json":
				tags["typescript"] = struct{}{}
			case "Chart.yaml":
				tags["helm"] = struct{}{}
			}
		}
	}

	out := DetectedTech{
		Sentinels:  uniqueSorted(sentinels),
		DetectedAt: core.NowISO(),
		RootPath:   root,
	}
	for tag := range tags {
		out.Tags = append(out.Tags, tag)
	}
	sort.Strings(out.Tags)
	return out
}

func workspaceDepth(rel string) int {
	dir := filepath.ToSlash(filepath.Dir(rel))
	if dir == "." || dir == "" {
		return 0
	}
	return len(strings.Split(dir, "/"))
}

func uniqueSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func detectNodePackage(tags map[string]struct{}, pkg string) {
	tags["node"] = struct{}{}
	if strings.Contains(pkg, "\"typescript\"") {
		tags["typescript"] = struct{}{}
	}
	check := func(tag, needle string) {
		if strings.Contains(pkg, needle) {
			tags[tag] = struct{}{}
		}
	}
	check("nextjs", "\"next\"")
	check("nextjs", "\"@vercel/next\"")
	check("react", "\"react\"")
	check("express", "\"express\"")
	check("fastify", "\"fastify\"")
	check("nestjs", "\"@nestjs/core\"")
	check("koa", "\"koa\"")
	check("hapi", "\"@hapi/hapi\"")
	check("hono", "\"hono\"")
	check("remix", "\"remix\"")
	check("remix", "\"@remix-run/")
	check("sveltekit", "\"@sveltejs/kit\"")
	check("svelte", "\"svelte\"")
	check("svelte", "\"@sveltejs/")
	check("astro", "\"astro\"")
	check("solidstart", "\"@solidjs/start\"")
	check("nuxt", "\"nuxt\"")
	check("graphql", "\"graphql\"")
	check("graphql", "\"@apollo/server\"")
}

func detectCargoPackage(tags map[string]struct{}, cargo string) {
	tags["rust"] = struct{}{}
	if strings.Contains(cargo, "axum") {
		tags["axum"] = struct{}{}
	}
	if strings.Contains(cargo, "actix-web") {
		tags["actix"] = struct{}{}
	}
	if strings.Contains(cargo, "rocket") {
		tags["rocket"] = struct{}{}
	}
	if strings.Contains(cargo, "warp") {
		tags["warp"] = struct{}{}
	}
}

func anyOf(root string, names ...string) bool {
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(root, n)); err == nil {
			return true
		}
	}
	return false
}

func concatRead(root string, names ...string) string {
	var out strings.Builder
	for _, n := range names {
		if b, err := os.ReadFile(filepath.Join(root, n)); err == nil {
			out.Write(b)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// TechJSONPath returns the on-disk cache path for DetectedTech.
func TechJSONPath(root core.DataRoot, projectID string) (string, error) {
	d, err := root.DataDir(projectID)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "tech.json"), nil
}

func ReadTechJSON(root core.DataRoot, projectID string) (*DetectedTech, error) {
	p, err := TechJSONPath(root, projectID)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to read symlinked tech cache: %s", p)
	}
	body, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var t DetectedTech
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func WriteTechJSON(root core.DataRoot, projectID string, t DetectedTech) error {
	p, err := TechJSONPath(root, projectID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(p); err == nil && info.Mode()&fs.ModeSymlink != 0 {
		return errors.New("refusing to overwrite symlinked tech cache")
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	body, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(p, 0o600)
}

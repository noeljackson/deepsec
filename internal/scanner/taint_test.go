package scanner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTaintedLinesGo(t *testing.T) {
	src := `package main

import "net/http"

func handle(r *http.Request) {
	user := r.URL.Query().Get("user")
	cmd := "id " + user
	_ = cmd
}
`
	tainted := taintedLines(src, "main.go")
	require.NotNil(t, tainted)
	// Line 6 contains r.URL.Query → tainted.
	_, ok := tainted[6]
	require.True(t, ok, "expected line 6 tainted, got %v", tainted)
	// Line 7 (cmd = ... + user) is NOT itself a source — user is downstream.
	_, ok = tainted[7]
	require.False(t, ok)
}

func TestTaintedLinesTypeScript(t *testing.T) {
	src := `import { Request } from 'express';

export function handle(req: Request) {
  const user = req.body.user;
  return exec('id ' + user);
}
`
	tainted := taintedLines(src, "handler.ts")
	require.NotNil(t, tainted)
	_, ok := tainted[4]
	require.True(t, ok, "expected line 4 tainted, got %v", tainted)
}

func TestTaintedLinesPython(t *testing.T) {
	src := `from flask import request

def handle():
    name = request.args.get('name')
    return f"hello {name}"
`
	tainted := taintedLines(src, "app.py")
	require.NotNil(t, tainted)
	_, ok := tainted[4]
	require.True(t, ok)
}

func TestTaintedLinesJavaAnnotation(t *testing.T) {
	src := `public class C {
  public void h(@RequestParam("u") String user) {
    System.out.println(user);
  }
}
`
	tainted := taintedLines(src, "C.java")
	require.NotNil(t, tainted)
	_, ok := tainted[2]
	require.True(t, ok)
}

func TestTaintedLinesUnknownExtensionFallsBackToGeneric(t *testing.T) {
	src := `# fictional language
req.body.user = whatever
`
	tainted := taintedLines(src, "thing.weird")
	require.NotNil(t, tainted)
	_, ok := tainted[2]
	require.True(t, ok)
}

func TestTaintedLinesNothingTainted(t *testing.T) {
	src := `package main

func main() {
	println("hello")
}
`
	require.Nil(t, taintedLines(src, "main.go"))
}

func TestLineWithinTaint(t *testing.T) {
	tainted := map[int]struct{}{5: {}, 20: {}}
	require.True(t, lineWithinTaint(5, 0, nil) == false)
	require.True(t, lineWithinTaint(5, 3, tainted))
	require.True(t, lineWithinTaint(7, 3, tainted))
	require.True(t, lineWithinTaint(2, 3, tainted))
	require.False(t, lineWithinTaint(15, 3, tainted)) // too far from 5, too far from 20
	require.False(t, lineWithinTaint(5, 0, tainted))  // radius=0 disables
}

func TestMatcherRequireTaintWithinDropsUntaintedCandidate(t *testing.T) {
	def := MatcherDef{
		Slug:               "test-taint-required",
		Description:        "test",
		FilePatterns:       []string{"**/*.go"},
		Patterns:           []string{`exec\.Command`},
		Label:              "exec",
		RequireTaintWithin: 3,
	}
	m, err := Compile(def)
	require.NoError(t, err)

	// File has exec.Command but no taint source nearby → drop.
	src := `package main

import "os/exec"

func main() {
	_ = exec.Command("ls")
}
`
	require.Empty(t, m.Match(src, "main.go"))

	// Same file but with a request source within 3 lines of exec.Command → keep.
	srcWithTaint := `package main

import (
	"net/http"
	"os/exec"
)

func handle(r *http.Request) {
	user := r.URL.Query().Get("user")
	_ = user
	_ = exec.Command("ls")
}
`
	matches := m.Match(srcWithTaint, "handler.go")
	require.Len(t, matches, 1)
}

func TestMatcherRequireTaintWithinZeroDisabled(t *testing.T) {
	def := MatcherDef{
		Slug:               "test-taint-disabled",
		Description:        "test",
		FilePatterns:       []string{"**/*.go"},
		Patterns:           []string{`exec\.Command`},
		Label:              "exec",
		RequireTaintWithin: 0,
	}
	m, err := Compile(def)
	require.NoError(t, err)
	src := `package main
import "os/exec"
func main() { _ = exec.Command("ls") }
`
	require.Len(t, m.Match(src, "main.go"), 1)
}

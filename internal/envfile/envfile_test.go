package envfile

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadMergesFilesAndDiscardsEnvironmentValues(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.yaml")
	secondDir := filepath.Join(dir, "second")
	if err := os.Mkdir(secondDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEnvFile(t, first, "schemaVersion: \"1\"\nname: before\nagent: shell\nworkspace: work\nports:\n  - sandbox: 3000\n    host: 4300\n    protocol: tcp\nenv:\n  TOKEN: secret-one\n  SHARED: old\nsandboxOptions:\n  cpus: 2\n")
	writeEnvFile(t, filepath.Join(secondDir, "sbxenv.yaml"), "schemaVersion: \"1\"\nname: after\nworkspace:\n  path: override\nadditionalWorkspaces:\n  - path: data\n    readOnly: true\nports:\n  - sandbox: 9222\n    hostIP: 127.0.0.1\nenv:\n  SHARED: secret-two\n  SECOND: value\nsandboxOptions:\n  memory: 2g\n")

	plan, err := Load([]string{first, secondDir})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Name != "after" || plan.Agent != "shell" {
		t.Fatalf("unexpected merged identity: %#v", plan)
	}
	if plan.Workspace != filepath.Join(secondDir, "override") {
		t.Fatalf("workspace = %q", plan.Workspace)
	}
	if len(plan.AdditionalWorkspaces) != 1 || plan.AdditionalWorkspaces[0] != (Workspace{Path: filepath.Join(secondDir, "data"), ReadOnly: true}) {
		t.Fatalf("additional workspaces = %#v", plan.AdditionalWorkspaces)
	}
	if !reflect.DeepEqual(plan.EnvironmentKeys, []string{"SECOND", "SHARED", "TOKEN"}) {
		t.Fatalf("environment keys = %#v", plan.EnvironmentKeys)
	}
	if plan.CPUs == nil || *plan.CPUs != 2 || plan.Memory != "2g" {
		t.Fatalf("resources = CPUs %v, memory %q", plan.CPUs, plan.Memory)
	}
	if len(plan.Ports) != 2 || plan.Ports[0].Sandbox != 3000 || plan.Ports[0].Host == nil || *plan.Ports[0].Host != 4300 || plan.Ports[0].Protocol != "tcp" || plan.Ports[1].Sandbox != 9222 || plan.Ports[1].Host != nil || plan.Ports[1].HostIP != "127.0.0.1" {
		t.Fatalf("ports = %#v", plan.Ports)
	}
}

func TestLoadForExecutionReturnsMergedValuesWithoutPuttingThemInPlan(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.yaml")
	second := filepath.Join(dir, "second.yaml")
	writeEnvFile(t, first, "schemaVersion: \"1\"\nagent: shell\nenv:\n  TOKEN: first-secret\n  SHARED: old\n")
	writeEnvFile(t, second, "schemaVersion: \"1\"\nenv:\n  SHARED: final-secret\n  MODE: test\n")

	plan, values, err := LoadForExecution([]string{first, second}, ArgumentOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(values)
	if values["TOKEN"] != "first-secret" || values["SHARED"] != "final-secret" || values["MODE"] != "test" {
		t.Fatalf("merged values are incorrect")
	}
	if strings.Contains(fmt.Sprint(plan), "first-secret") || strings.Contains(fmt.Sprint(plan), "final-secret") {
		t.Fatal("runtime environment values leaked into the preview plan")
	}
}

func TestLoadDefaultMergesUserDefaultsBeforeCurrentDirectory(t *testing.T) {
	root := t.TempDir()
	homeDir := filepath.Join(root, "home")
	workingDir := filepath.Join(root, "project")
	if err := os.Mkdir(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEnvFile(t, filepath.Join(homeDir, ".sbxenv.yaml"), "schemaVersion: \"1\"\nagent: shell\nname: shared\nworkspace: shared-work\nenv:\n  SHARED: hidden\n")
	writeEnvFile(t, filepath.Join(workingDir, "sbxenv.yaml"), "schemaVersion: \"1\"\nagent: shell\nname: project\nworkspace: project-work\nenv:\n  PROJECT: hidden\n")

	plan, err := LoadDefault(homeDir, workingDir)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Name != "project" || plan.Workspace != filepath.Join(workingDir, "project-work") {
		t.Fatalf("project values did not override defaults: %#v", plan)
	}
	if !reflect.DeepEqual(plan.EnvironmentKeys, []string{"PROJECT", "SHARED"}) {
		t.Fatalf("merged environment keys = %#v", plan.EnvironmentKeys)
	}

	explicit, err := Load([]string{workingDir})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(explicit.EnvironmentKeys, []string{"PROJECT"}) {
		t.Fatalf("explicit path unexpectedly included user defaults: %#v", explicit.EnvironmentKeys)
	}
}

func TestLoadDefaultAllowsEitherHomeDefaultsOrProjectFile(t *testing.T) {
	root := t.TempDir()
	homeDir := filepath.Join(root, "home")
	workingDir := filepath.Join(root, "project")
	if err := os.Mkdir(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEnvFile(t, filepath.Join(workingDir, "sbxenv.yaml"), "schemaVersion: \"1\"\nagent: shell\n")
	if _, err := LoadDefault(homeDir, workingDir); err != nil {
		t.Fatalf("missing optional home defaults rejected: %v", err)
	}
	writeEnvFile(t, filepath.Join(homeDir, ".sbxenv.yaml"), "schemaVersion: \"1\"\nagent: shell\nworkspace: ${{ env.projectDir }}\n")
	plan, err := LoadDefault(homeDir, root)
	if err != nil {
		t.Fatalf("home-only environment defaults rejected: %v", err)
	}
	if plan.Workspace != root {
		t.Fatalf("home default workspace=%q, want %q", plan.Workspace, root)
	}
	if _, err := LoadDefault(filepath.Join(root, "empty-home"), root); err == nil {
		t.Fatal("missing both project and home environment files accepted")
	}
}

func TestLoadExpandsProjectAndFileDirectoryReferences(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "project")
	baseDir := filepath.Join(root, "defaults")
	if err := os.Mkdir(projectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(baseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(baseDir, "base.yaml")
	project := filepath.Join(projectDir, "sbxenv.yaml")
	writeEnvFile(t, base, "schemaVersion: \"1\"\nagent: shell\nworkspace: \"${{ env.projectDir }}/base\"\nadditionalWorkspaces:\n  - path: \"${{ env.fileDir }}/shared\"\n")
	writeEnvFile(t, project, "schemaVersion: \"1\"\nworkspace: \"${{ env.fileDir }}/src\"\n")

	plan, err := Load([]string{project, base})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(projectDir, "base"); plan.Workspace != want {
		t.Fatalf("workspace = %q, want %q", plan.Workspace, want)
	}
	if len(plan.AdditionalWorkspaces) != 1 {
		t.Fatalf("additional workspaces = %#v", plan.AdditionalWorkspaces)
	}
	if want := filepath.Join(baseDir, "shared"); plan.AdditionalWorkspaces[0].Path != want {
		t.Fatalf("additional workspace = %q, want %q", plan.AdditionalWorkspaces[0].Path, want)
	}
}

func TestLoadDefaultExpandsProjectDirectoryInHomeDefaults(t *testing.T) {
	root := t.TempDir()
	homeDir := filepath.Join(root, "home")
	workingDir := filepath.Join(root, "project")
	if err := os.Mkdir(homeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEnvFile(t, filepath.Join(homeDir, ".sbxenv.yaml"), "schemaVersion: \"1\"\nagent: shell\nworkspace: \"${{ env.projectDir }}\"\n")
	writeEnvFile(t, filepath.Join(workingDir, "sbxenv.yaml"), "schemaVersion: \"1\"\n")

	plan, err := LoadDefault(homeDir, workingDir)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Workspace != workingDir {
		t.Fatalf("workspace = %q, want project directory %q", plan.Workspace, workingDir)
	}
}

func TestLoadRejectsUnknownDirectoryReferences(t *testing.T) {
	cases := map[string]string{
		"workspace":   "workspace: \"${{ env.unknown }}\"\n",
		"other field": "env:\n  TOKEN: ${{ env.secret.value }}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sbxenv.yaml")
			writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\n"+body)
			if _, err := Load([]string{path}); err == nil {
				t.Fatal("unknown environment reference accepted")
			}
		})
	}
}

func TestLoadAllowsExpandedDirectoryWithReferenceSyntaxInName(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "project-${{literal}}")
	if err := os.Mkdir(projectDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(projectDir, "sbxenv.yaml")
	writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\nworkspace: \"${{ env.projectDir }}/src\"\n")

	plan, err := Load([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(projectDir, "src"); plan.Workspace != want {
		t.Fatalf("workspace = %q, want %q", plan.Workspace, want)
	}
}

func TestLoadValidatesDeclaredArgumentsWithoutRetainingValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbxenv.yaml")
	writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\nargs:\n  channel:\n    default: stable\n    enum: [stable, preview]\n  build:\n    required: true\n    pattern: '[A-Z0-9]+'\n")
	argumentFile := filepath.Join(t.TempDir(), "args.txt")
	writeEnvFile(t, argumentFile, "build=BUILD42\n")

	plan, err := LoadWithArguments([]string{path}, ArgumentOverrides{
		Files:  []string{argumentFile},
		Values: []string{"channel=preview", "build=CLI77"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.ArgumentNames, []string{"build", "channel"}) {
		t.Fatalf("argument names = %#v", plan.ArgumentNames)
	}
	for _, value := range []string{"stable", "preview", "BUILD42", "CLI77"} {
		if strings.Contains(fmt.Sprintf("%#v", plan), value) {
			t.Fatalf("argument value %q was retained in the plan", value)
		}
	}
}

func TestLoadArgumentDefaultsAndFilesOverrideInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbxenv.yaml")
	writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\nargs:\n  mode:\n    default: stable\n    enum: [stable, preview, nightly]\n")
	first := filepath.Join(t.TempDir(), "first.args")
	second := filepath.Join(t.TempDir(), "second.args")
	writeEnvFile(t, first, "# base value is shadowed by the next file\n  \nmode=not-in-enum\n")
	writeEnvFile(t, second, "mode=nightly\n")
	plan, err := LoadWithArguments([]string{path}, ArgumentOverrides{Files: []string{first, second}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.ArgumentNames, []string{"mode"}) {
		t.Fatalf("argument names = %#v", plan.ArgumentNames)
	}
}

func TestLoadBoundsCombinedArgumentFileInput(t *testing.T) {
	envPath := filepath.Join(t.TempDir(), "sbxenv.yaml")
	writeEnvFile(t, envPath, "schemaVersion: \"1\"\nagent: shell\nargs:\n  mode:\n    default: stable\n")
	argumentPath := filepath.Join(t.TempDir(), "args.txt")
	writeEnvFile(t, argumentPath, "mode=stable\n"+strings.Repeat("#", maxFileSize-12))
	files := make([]string, maxArgumentInputSize/maxFileSize+1)
	for i := range files {
		files[i] = argumentPath
	}
	if _, err := LoadWithArguments([]string{envPath}, ArgumentOverrides{Files: files}); err == nil || !strings.Contains(err.Error(), "exceed size limit") {
		t.Fatalf("LoadWithArguments() error = %v, want combined input size error", err)
	}
}

func TestResolveArgumentValuesBoundsValueCount(t *testing.T) {
	arguments := make(map[string]argumentDeclaration, maxYAMLNodes+1)
	values := make([]string, maxYAMLNodes+1)
	for i := range values {
		name := "value_" + strconv.Itoa(i)
		arguments[name] = argumentDeclaration{Default: stringPointer("x")}
		values[i] = name + "=x"
	}
	if _, _, err := resolveArgumentValues(arguments, ArgumentOverrides{Values: values}); err == nil || !strings.Contains(err.Error(), "too many environment argument values") {
		t.Fatalf("resolveArgumentValues() error = %v, want argument count limit error", err)
	}
}

func TestResolveArgumentValuesBoundsCLIInputBytes(t *testing.T) {
	value := strings.Repeat("x", maxArgumentInputSize+1)
	if _, _, err := resolveArgumentValues(nil, ArgumentOverrides{Values: []string{value}}); err == nil || !strings.Contains(err.Error(), "exceed size limit") {
		t.Fatalf("resolveArgumentValues() error = %v, want CLI input size error", err)
	}
}

func stringPointer(value string) *string { return &value }

func TestLoadRejectsInvalidBaseArgumentDefaultEvenWhenOverridden(t *testing.T) {
	first := filepath.Join(t.TempDir(), "base.yaml")
	second := filepath.Join(t.TempDir(), "override.yaml")
	writeEnvFile(t, first, "schemaVersion: \"1\"\nagent: shell\nargs:\n  mode:\n    default: invalid\n    enum: [valid]\n")
	writeEnvFile(t, second, "schemaVersion: \"1\"\nargs:\n  mode:\n    default: valid\n    enum: [valid]\n")
	if _, err := Load([]string{first, second}); err == nil {
		t.Fatal("Load() succeeded with an invalid base argument default")
	}
}

func TestLoadInterpolatesArgumentReferencesWithoutRetainingValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbxenv.yaml")
	writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\nworkspace: ${{ env.args.workspace }}\nargs:\n  workspace:\n    required: true\n  cpus:\n    default: \"4\"\n  suffix:\n    default: preview\nenv:\n  API_URL: 'https://${{ env.args.workspace }}/v1'\n  DEPLOYMENT: ${{ env.args.suffix }}\nsandboxOptions:\n  cpus: ${{ env.args.cpus }}\n")
	plan, err := LoadWithArguments([]string{path}, ArgumentOverrides{Values: []string{"workspace=api.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.ArgumentNames, []string{"cpus", "suffix", "workspace"}) {
		t.Fatalf("argument names = %#v", plan.ArgumentNames)
	}
	if plan.CPUs == nil || *plan.CPUs != 4 {
		t.Fatalf("substituted CPU value = %#v, want 4", plan.CPUs)
	}
	if want := filepath.Join(filepath.Dir(path), "api.example"); plan.Workspace != want {
		t.Fatalf("interpolated workspace = %q, want %q", plan.Workspace, want)
	}
	if !reflect.DeepEqual(plan.EnvironmentKeys, []string{"API_URL", "DEPLOYMENT"}) {
		t.Fatalf("environment keys = %#v", plan.EnvironmentKeys)
	}
}

func TestLoadRejectsUnknownAndSelfReferencingArguments(t *testing.T) {
	cases := map[string]string{
		"unknown":        "env:\n  TOKEN: ${{ env.args.missing }}\n",
		"self reference": "args:\n  name:\n    default: ${{ env.args.name }}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sbxenv.yaml")
			writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\n"+body)
			if _, err := LoadWithArguments([]string{path}, ArgumentOverrides{}); err == nil {
				t.Fatal("LoadWithArguments() succeeded; want rejection")
			}
		})
	}
}

func TestLoadAllowsEscapedReferenceLiteralInArgumentDefinition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbxenv.yaml")
	writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\nargs:\n  literal:\n    default: '$${{ env.args.other }}'\n")
	if _, err := Load([]string{path}); err != nil {
		t.Fatalf("Load() rejected escaped literal: %v", err)
	}
}

func TestInterpolateArgumentReferencesPreservesEscapedAndSubstitutedText(t *testing.T) {
	node := yaml.Node{Kind: yaml.ScalarNode, Tag: yamlStringTag, Style: yaml.SingleQuotedStyle, Value: "$${{ env.args.first }} / ${{ env.args.first }}"}
	values := map[string]string{"first": "${{ env.projectDir }}"}
	if err := interpolateScalar(&node, values, "/project", "/project"); err != nil {
		t.Fatal(err)
	}
	want := "${{ env.args.first }} / ${{ env.projectDir }}"
	if node.Value != want {
		t.Fatalf("interpolated scalar = %q, want %q", node.Value, want)
	}
}

func TestReplaceArgumentReferencesRejectsExpandedValueOverLimit(t *testing.T) {
	source := "${{ env.args.value }}${{ env.args.value }}"
	if _, err := replaceEnvironmentReferences(source, environmentReference.FindAllStringSubmatchIndex(source, -1), map[string]string{"value": strings.Repeat("x", maxFileSize/2+1)}, "", ""); err == nil {
		t.Fatal("replaceEnvironmentReferences() succeeded beyond the expansion limit")
	}
}

func TestInterpolateDirectoryReferencesInAllYAMLValues(t *testing.T) {
	node := yaml.Node{Kind: yaml.ScalarNode, Tag: yamlStringTag, Style: yaml.SingleQuotedStyle, Value: "${{ env.fileDir }}:${{ env.projectDir }}"}
	if err := interpolateScalar(&node, nil, "/declaring/file", "/project"); err != nil {
		t.Fatal(err)
	}
	if want := "/declaring/file:/project"; node.Value != want {
		t.Fatalf("interpolated scalar = %q, want %q", node.Value, want)
	}
}

func TestLoadExpandsDirectoryReferencesBeyondWorkspaceFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbxenv.yaml")
	writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\nenv:\n  PROJECT_ROOT: ${{ env.projectDir }}\n  DECLARING_FILE: ${{ env.fileDir }}\n")
	root, _, _, err := readDocumentNode(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := interpolateEnvironmentReferences(root, nil, filepath.Dir(path), filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	doc, err := decodeDocumentNode(root)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"PROJECT_ROOT": filepath.Dir(path), "DECLARING_FILE": filepath.Dir(path)} {
		if doc.Env[key] != want {
			t.Fatalf("env[%s] = %q, want %q", key, doc.Env[key], want)
		}
	}
}

func TestLoadRejectsInvalidArgumentDeclarationsAndValues(t *testing.T) {
	cases := map[string]struct {
		document string
		values   []string
	}{
		"missing required value": {document: "args:\n  channel:\n    required: true\n"},
		"enum mismatch":          {document: "args:\n  channel:\n    default: stable\n    enum: [stable, preview]\n", values: []string{"channel=nightly"}},
		"pattern mismatch":       {document: "args:\n  build:\n    required: true\n    pattern: '[A-Z]+'\n", values: []string{"build=lower"}},
		"undeclared value":       {document: "args:\n  channel:\n    default: stable\n", values: []string{"extra=value"}},
		"invalid pair syntax":    {document: "args:\n  channel:\n    default: stable\n", values: []string{"not-a-pair"}},
		"default and required":   {document: "args:\n  channel:\n    default: stable\n    required: true\n"},
		"enum and pattern":       {document: "args:\n  channel:\n    default: stable\n    enum: [stable]\n    pattern: stable\n"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sbxenv.yaml")
			writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\n"+testCase.document)
			if _, err := LoadWithArguments([]string{path}, ArgumentOverrides{Values: testCase.values}); err == nil {
				t.Fatal("LoadWithArguments() succeeded; want rejection")
			}
		})
	}
}

func TestLoadRejectsUnsupportedFieldsAndMalformedDocuments(t *testing.T) {
	cases := map[string]string{
		"unknown field":           "schemaVersion: \"1\"\nagent: shell\nsecretSource: host\n",
		"nested unknown field":    "schemaVersion: \"1\"\nagent: shell\nworkspace:\n  path: work\n  writable: false\n",
		"second document":         "schemaVersion: \"1\"\nagent: shell\n---\nschemaVersion: \"1\"\nagent: shell\n",
		"missing agent":           "schemaVersion: \"1\"\nname: x\n",
		"invalid cpu":             "schemaVersion: \"1\"\nagent: shell\nsandboxOptions:\n  cpus: 0\n",
		"invalid memory":          "schemaVersion: \"1\"\nagent: shell\nsandboxOptions:\n  memory: 1k\n",
		"duplicate workspace key": "schemaVersion: \"1\"\nagent: shell\nworkspace:\n  path: a\n  path: b\n",
		"missing sandbox port":    "schemaVersion: \"1\"\nagent: shell\nports:\n  - host: 3000\n",
		"invalid port protocol":   "schemaVersion: \"1\"\nagent: shell\nports:\n  - sandbox: 3000\n    protocol: sctp\n",
		"invalid host ip":         "schemaVersion: \"1\"\nagent: shell\nports:\n  - sandbox: 3000\n    hostIP: example.com\n",
		"out of range port":       "schemaVersion: \"1\"\nagent: shell\nports:\n  - sandbox: 65536\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "env.yaml")
			writeEnvFile(t, path, body)
			if _, err := Load([]string{path}); err == nil {
				t.Fatal("Load() succeeded; want rejection")
			}
		})
	}
}

func TestLoadBoundsInputSizeAndRequiresExplicitPath(t *testing.T) {
	if _, err := Load(nil); err == nil {
		t.Fatal("Load(nil) succeeded")
	}
	path := filepath.Join(t.TempDir(), "large.yaml")
	writeEnvFile(t, path, "schemaVersion: \"1\"\nagent: shell\n"+strings.Repeat("#", maxFileSize))
	if _, err := Load([]string{path}); err == nil {
		t.Fatal("oversized input succeeded")
	}
}

func TestDecodeDocumentRejectsAliasesAndDeepNesting(t *testing.T) {
	alias := []byte("schemaVersion: \"1\"\nagent: &agent shell\nname: *agent\n")
	if _, err := decodeDocument(alias); err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("alias input error = %v, want alias rejection", err)
	}
	deep := "schemaVersion: \"1\"\nagent: shell\nsandboxOptions:\n  nested: " + strings.Repeat("[", maxYAMLDepth) + "x" + strings.Repeat("]", maxYAMLDepth) + "\n"
	if _, err := decodeDocument([]byte(deep)); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("deep input error = %v, want nesting rejection", err)
	}
}

func FuzzDecodeDocument(f *testing.F) {
	f.Add([]byte("schemaVersion: \"1\"\nagent: shell\nenv:\n  API_TOKEN: secret\n"))
	f.Add([]byte("schemaVersion: \"1\"\nagent: shell\nworkspace:\n  path: work\n"))
	f.Add([]byte("schemaVersion: \"1\"\nname: ${{ env.args.name }}\nadditionalWorkspaces:\n  - path: ${{ env.args.path }}\nports:\n  - sandbox: ${{ env.args.port }}\nargs:\n  name:\n    default: sandbox\n"))
	f.Add([]byte("schemaVersion: \"1\"\nagent: shell\n---\nsecond: document\n"))
	f.Add([]byte("{invalid yaml"))
	f.Add([]byte("schemaVersion: \"1\"\nagent: &agent shell\nname: *agent\n"))
	f.Add([]byte(strings.Repeat("x", maxFileSize+1)))
	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := decodeDocumentNodeFromBytes(data)
		if err == nil {
			_ = findArgumentReferenceUsage(root)
		}
		if err != nil {
			return
		}
		doc, err := decodeDocument(data)
		if err == nil {
			_ = doc.validate()
		}
	})
}

func FuzzParseArgumentValues(f *testing.F) {
	f.Add("CHANNEL=preview")
	f.Add("missing-separator")
	f.Add("API_KEY=one=two")
	f.Fuzz(func(t *testing.T, value string) {
		values := make(map[string]string)
		if err := parseArgumentValues([]string{value}, values); err == nil {
			for name := range values {
				if !argumentIdentifier.MatchString(name) {
					t.Fatalf("accepted invalid argument name %q", name)
				}
			}
		}
	})
}

func FuzzInterpolateEnvironmentReferences(f *testing.F) {
	f.Add("${{ env.args.value }}", "plain")
	f.Add("prefix-${{ env.args.value }}-suffix", "with spaces")
	f.Add("$${{ env.args.value }}", "literal")
	f.Fuzz(func(t *testing.T, source, value string) {
		node := yaml.Node{Kind: yaml.ScalarNode, Tag: yamlStringTag, Style: yaml.SingleQuotedStyle, Value: source}
		err := interpolateScalar(&node, map[string]string{"value": value}, "", "")
		if err == nil && len(node.Value) > maxFileSize {
			t.Fatalf("interpolated scalar length %d exceeds limit", len(node.Value))
		}
	})
}

func writeEnvFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

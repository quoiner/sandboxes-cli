package command

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

type runClient struct {
	fakeClient
	sandboxes *runSandbox
	sessions  *fakeSessions
}

type runSecretService []sdk.ServiceSecret

func (s runSecretService) Set(context.Context, string, sdk.SecretScope, string, []byte) (sdk.ServiceSecret, error) {
	return sdk.ServiceSecret{}, nil
}
func (s runSecretService) Create(context.Context, string, sdk.SecretScope, string, []byte) (sdk.ServiceSecret, error) {
	return sdk.ServiceSecret{}, nil
}

func (s runSecretService) List(context.Context) ([]sdk.ServiceSecret, error) {
	return []sdk.ServiceSecret(s), nil
}

func (s runSecretService) Remove(context.Context, string, sdk.SecretScope, string) (bool, error) {
	return false, nil
}

func (c runClient) Sandboxes() sdk.SandboxService    { return c.sandboxes }
func (c runClient) PolicyService() sdk.PolicyService { return fakePolicyCheck{sandboxes: c.sandboxes} }
func (c runClient) SessionExecutor() sdk.SessionExecutor {
	return c.sessions
}

type runSandbox struct {
	fakeSandbox
	items       []sdk.Sandbox
	created     sdk.CreateRequest
	createCalls int
	startCalls  int
	deleteCalls int
	deleteID    string
	deleteForce bool
	deleteErr   error
}

func (s *runSandbox) Create(_ context.Context, req sdk.CreateRequest) (*sdk.Operation, error) {
	s.createCalls++
	s.created = req
	s.created.Env = make(map[string]string, len(req.Env))
	for key, value := range req.Env {
		s.created.Env[key] = value
	}
	item := sdk.Sandbox{ID: "sb-run", Name: req.Name, State: sdk.StateRunning, Image: req.Image, Workspace: req.Workspace}
	s.items = append(s.items, item)
	return &sdk.Operation{ID: "op-create", SandboxID: item.ID, Kind: "create", State: sdk.StateDone}, nil
}

func (s *runSandbox) Get(_ context.Context, id string) (*sdk.Sandbox, error) {
	for i := range s.items {
		if s.items[i].ID == id || s.items[i].Name == id {
			item := s.items[i]
			return &item, nil
		}
	}
	return nil, errors.New("not found")
}

func (s *runSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	items := append([]sdk.Sandbox(nil), s.items...)
	return &sdk.Page[sdk.Sandbox]{Items: items}, nil
}

func (s *runSandbox) Delete(_ context.Context, id string, options sdk.DeleteOptions) (*sdk.Operation, error) {
	s.deleteCalls++
	s.deleteID = id
	s.deleteForce = options.Force
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	return &sdk.Operation{ID: "op-delete", State: sdk.StateDone}, nil
}

func (s *runSandbox) Start(_ context.Context, id string) (*sdk.Operation, error) {
	for i := range s.items {
		if s.items[i].ID == id {
			s.items[i].State = sdk.StateRunning
			s.startCalls++
			return &sdk.Operation{ID: "op-start", State: sdk.StateDone}, nil
		}
	}
	return nil, errors.New("not found")
}

type fakeSessions struct {
	req    sdk.SessionRequest
	opened bool
	closed bool
	input  []byte
}

func (s *fakeSessions) OpenSession(_ context.Context, req sdk.SessionRequest) (sdk.ExecSession, error) {
	s.req = req
	s.req.Env = append([]string(nil), req.Env...)
	s.opened = true
	return &fakeSession{sessions: s}, nil
}

type fakeSession struct {
	sessions *fakeSessions
	exited   bool
}

func (s *fakeSession) SendInput(data []byte) error {
	s.sessions.input = append(s.sessions.input, data...)
	return nil
}
func (s *fakeSession) CloseInput() error {
	s.sessions.closed = true
	return nil
}
func (s *fakeSession) Resize(sdk.TerminalSize) error { return nil }
func (s *fakeSession) Receive() (sdk.SessionFrame, error) {
	if s.exited {
		return sdk.SessionFrame{}, io.EOF
	}
	s.exited = true
	code := 0
	return sdk.SessionFrame{ExitCode: &code}, nil
}

func runTestRunner(t *testing.T, client sdk.Client, input string) (*Runner, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, stderr bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &stderr, In: strings.NewReader(input), Socket: "unused",
		NewClient: func(string) (sdk.Client, error) { return client, nil },
	}
	return runner, &out, &stderr
}

func TestRunCreatesStartsAndAttachesShell(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "dev", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.createCalls != 1 || sandboxes.startCalls != 0 {
		t.Fatalf("create=%d start=%d", sandboxes.createCalls, sandboxes.startCalls)
	}
	if sandboxes.created.Name != "dev" || sandboxes.created.Workspace != workspace {
		t.Fatalf("unexpected create request: %#v", sandboxes.created)
	}
	if !sessions.opened || strings.Join(sessions.req.Argv, "\x00") != "bash\x00-l" || sessions.req.TTY {
		t.Fatalf("unexpected session: %#v", sessions.req)
	}
	if sessions.req.SandboxID != "sb-run" || !sessions.closed {
		t.Fatalf("session id=%q closed=%t", sessions.req.SandboxID, sessions.closed)
	}
}

func TestRunKitRequestsHostOpenAIOAuthAndAddsProxyReference(t *testing.T) {
	kitPath := filepath.Join(t.TempDir(), "codex-oauth.yaml")
	kitBody := `apiVersion: rheic.dev/v1alpha1
kind: Kit
metadata: {name: codex-oauth}
spec:
  agent: codex
  credentials:
    - service: openai
      oauth:
        resourceHosts: [api.openai.com]
`
	if err := os.WriteFile(kitPath, []byte(kitBody), 0o600); err != nil {
		t.Fatal(err)
	}
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{
		fakeClient: fakeClient{accounts: &fakeAccounts{}}, sandboxes: sandboxes, sessions: sessions,
	}, "")
	if code := runner.Run(context.Background(), []string{"run", "--kit", kitPath}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.createCalls != 1 || sandboxes.created.Env["OPENAI_API_KEY"] != "${oauth:openai}" {
		t.Fatalf("create calls=%d env=%v", sandboxes.createCalls, sandboxes.created.Env)
	}
	if len(sandboxes.created.OAuthCredentials) != 0 {
		t.Fatalf("fixed OpenAI provider config must stay daemon-managed: %#v", sandboxes.created.OAuthCredentials)
	}
	if !reflect.DeepEqual(sessions.req.Env, []string{"OPENAI_API_KEY=${oauth:openai}"}) {
		t.Fatalf("agent env=%q", sessions.req.Env)
	}
}

func TestRunCodexUsesHostOAuthWhenNoStoredAPIKey(t *testing.T) {
	sandboxes := &runSandbox{}
	runner, out, stderr := runTestRunner(t, runClient{
		fakeClient: fakeClient{accounts: &fakeAccounts{}, secrets: runSecretService{}},
		sandboxes:  sandboxes,
		sessions:   &fakeSessions{},
	}, "")
	if code := runner.Run(context.Background(), []string{"run", "--detach", "codex"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if got := sandboxes.created.Env["OPENAI_API_KEY"]; got != "${oauth:openai}" {
		t.Fatalf("Codex env=%q, want host OAuth reference", got)
	}
}

func TestRunCodexPrefersStoredAPIKey(t *testing.T) {
	sandboxes := &runSandbox{}
	runner, out, stderr := runTestRunner(t, runClient{
		fakeClient: fakeClient{accounts: &fakeAccounts{}, secrets: runSecretService{{Service: "openai", Scope: sdk.SecretScopeGlobal}}},
		sandboxes:  sandboxes,
		sessions:   &fakeSessions{},
	}, "")
	if code := runner.Run(context.Background(), []string{"run", "--detach", "codex"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if got := sandboxes.created.Env["OPENAI_API_KEY"]; got != "${proxy:openai}" {
		t.Fatalf("Codex env=%q, want service-secret proxy reference", got)
	}
}

func TestRunClaudeUsesHostAnthropicSecretProxy(t *testing.T) {
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{
		fakeClient: fakeClient{secrets: runSecretService{{Service: "anthropic", Scope: sdk.SecretScopeGlobal}}},
		sandboxes:  sandboxes,
		sessions:   sessions,
	}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "claude-proxy-test", "--detach", "claude"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if got := sandboxes.created.Env["ANTHROPIC_API_KEY"]; got != "${proxy:anthropic}" {
		t.Fatalf("Claude create env=%q, want host-managed proxy reference", got)
	}
}

func TestRunGeminiUsesHostGoogleSecretProxy(t *testing.T) {
	sandboxes := &runSandbox{}
	runner, out, stderr := runTestRunner(t, runClient{
		fakeClient: fakeClient{secrets: runSecretService{{Service: googleService, Scope: sdk.SecretScopeGlobal}}},
		sandboxes:  sandboxes,
		sessions:   &fakeSessions{},
	}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "gemini-proxy-test", "--detach", "gemini"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if got := sandboxes.created.Env[geminiAPIKeyEnv]; got != "${proxy:google}" {
		t.Fatalf("Gemini create env=%q, want host-managed proxy reference", got)
	}
}

func TestAgentSpecificProviderSecretsActivateOnlyFixedProxyRoutes(t *testing.T) {
	cases := []struct {
		name    string
		service string
		want    map[string]string
	}{
		{
			name: "copilot", service: githubService,
			want: map[string]string{
				"GH_TOKEN":                       "${proxy:github}",
				"RHEIC_PROXY_GITHUB_WEB":         "${proxy:github-web}",
				"RHEIC_PROXY_GITHUB_RAW":         "${proxy:github-raw}",
				"RHEIC_PROXY_GITHUB_GIST":        "${proxy:github-gist}",
				"RHEIC_PROXY_GITHUB_COPILOT":     "${proxy:github-copilot}",
				"RHEIC_PROXY_GITHUB_COPILOT_API": "${proxy:github-copilot-api}",
			},
		},
		{
			name: "cursor", service: cursorService,
			want: map[string]string{
				"CURSOR_API_KEY":            "${proxy:cursor}",
				"RHEIC_PROXY_CURSOR_API3":   "${proxy:cursor-api3}",
				"RHEIC_PROXY_CURSOR_REPO42": "${proxy:cursor-repo42}",
				"RHEIC_PROXY_CURSOR_WEB":    "${proxy:cursor-web}",
			},
		},
		{
			name: "droid", service: droidService,
			want: map[string]string{
				"FACTORY_API_KEY":         "${proxy:droid}",
				"RHEIC_PROXY_DROID_APP":   "${proxy:droid-app}",
				"RHEIC_PROXY_DROID_RELAY": "${proxy:droid-relay}",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sandboxes := &runSandbox{}
			runner, out, stderr := runTestRunner(t, runClient{
				fakeClient: fakeClient{secrets: runSecretService{{Service: tc.service, Scope: sdk.SecretScopeGlobal}}},
				sandboxes:  sandboxes,
				sessions:   &fakeSessions{},
			}, "")
			if code := runner.Run(context.Background(), []string{"run", "--name", "proxy-agent-test", "--detach", tc.name}); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			if !reflect.DeepEqual(sandboxes.created.Env, tc.want) {
				t.Fatalf("create env=%v, want fixed proxy references %v", sandboxes.created.Env, tc.want)
			}
		})
	}
}

func TestRunClaudeDoesNotReplaceExplicitCredentialConfiguration(t *testing.T) {
	client := runClient{fakeClient: fakeClient{secrets: runSecretService{{Service: "anthropic", Scope: sdk.SecretScopeGlobal}}}, sandboxes: &runSandbox{}, sessions: &fakeSessions{}}
	for _, entry := range []string{"ANTHROPIC_API_KEY=proxy-managed", "ANTHROPIC_BASE_URL=http://localhost:1234"} {
		t.Run(strings.ReplaceAll(entry, "=", "_"), func(t *testing.T) {
			got, err := prepareAgentCredentials(context.Background(), client, "claude", "", []string{entry})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, []string{entry}) {
				t.Fatalf("env=%q, want explicit override preserved", got)
			}
		})
	}
}

func TestMultiProviderAgentsOnlyReceiveScopedProxyReferences(t *testing.T) {
	secrets := runSecretService{
		{Service: "openai", Scope: sdk.SecretScopeGlobal},
		{Service: "anthropic", Scope: sdk.SecretScopeSandbox, SandboxName: "agent-test"},
		{Service: googleService, Scope: sdk.SecretScopeGlobal},
		{Service: "groq", Scope: sdk.SecretScopeSandbox, SandboxName: "another-sandbox"},
	}
	for _, agent := range []string{"opencode", "docker-agent"} {
		t.Run(agent, func(t *testing.T) {
			sandboxes := &runSandbox{}
			runner, out, stderr := runTestRunner(t, runClient{
				fakeClient: fakeClient{secrets: secrets},
				sandboxes:  sandboxes,
				sessions:   &fakeSessions{},
			}, "")
			if code := runner.Run(context.Background(), []string{"run", "--name", "agent-test", "--detach", "--env", "MISTRAL_API_KEY=explicit-placeholder", agent}); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			want := map[string]string{
				"MISTRAL_API_KEY":   "explicit-placeholder",
				"ANTHROPIC_API_KEY": "${proxy:anthropic}",
				geminiAPIKeyEnv:     "${proxy:google}",
				"OPENAI_API_KEY":    "${proxy:openai}",
			}
			if !reflect.DeepEqual(sandboxes.created.Env, want) {
				t.Fatalf("create env=%v, want only applicable proxy references %v", sandboxes.created.Env, want)
			}
		})
	}
}

func TestValidateOAuthProxyEnvironmentRejectsOverrides(t *testing.T) {
	if err := validateOAuthProxyEnvironment([]string{openAIOAuthEnvRef, "PATH=/bin"}); err != nil {
		t.Fatalf("valid OAuth proxy environment rejected: %v", err)
	}
	for _, env := range [][]string{
		{openAIOAuthEnvRef, "OPENAI_API_KEY=explicit-key"},
		{openAIOAuthEnvRef, "OPENAI_BASE_URL=https://attacker.invalid"},
		{openAIOAuthEnvRef, openAIOAuthEnvRef},
	} {
		if err := validateOAuthProxyEnvironment(env); err == nil {
			t.Errorf("accepted conflicting OAuth proxy environment %q", env)
		}
	}
}

func TestBuildExecEnvRejectsOAuthConflictsAcrossEnvFileAndFlags(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "oauth.env")
	if err := os.WriteFile(envFile, []byte(openAIOAuthEnvRef+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildExecEnv([]string{"OPENAI_API_KEY=explicit"}, []string{envFile}); err == nil {
		t.Fatal("accepted explicit OpenAI key alongside OAuth kit reference")
	}
	if _, err := buildExecEnv([]string{"OPENAI_BASE_URL=https://attacker.invalid"}, []string{envFile}); err == nil {
		t.Fatal("accepted OpenAI base URL alongside OAuth kit reference")
	}
}

func TestRunDetachPrintsSandboxIDWithoutAttaching(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "-d", "--name", "dev", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if strings.TrimSpace(out.String()) != "sb-run" || sessions.opened {
		t.Fatalf("stdout=%q opened=%t", out.String(), sessions.opened)
	}
}

func TestRunReusesAndRestartsExistingSandbox(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateStopped, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "dev"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.createCalls != 0 || sandboxes.startCalls != 1 {
		t.Fatalf("create=%d start=%d", sandboxes.createCalls, sandboxes.startCalls)
	}
	if !sessions.opened || sessions.req.SandboxID != "sb-old" || strings.Join(sessions.req.Argv, "\x00") != "bash\x00-l" {
		t.Fatalf("unexpected session: %#v", sessions.req)
	}
}

func TestRunRejectsUnimplementedAndUnknownAgents(t *testing.T) {
	for _, agent := range []string{"cline", "not-an-agent"} {
		called := false
		runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
			called = true
			return runClient{}, nil
		}}
		if code := runner.Run(context.Background(), []string{"run", agent, "."}); code != 2 || called {
			t.Fatalf("agent %q: exit=%d client-called=%t", agent, code, called)
		}
	}
}

func TestRunRejectsExtraWorkspacesAndInvalidFlags(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--name", "", "shell", "."},
		{"run", "-e", "1BAD=x", "shell", "."},
		{"run", "-e", "OPENAI_API_KEY=${secret:openai}", "shell", "."},
		{"run", "--rm", "--detach", "shell", "."},
	} {
		called := false
		runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
			called = true
			return runClient{}, nil
		}}
		if code := runner.Run(context.Background(), args); code != 2 || called {
			t.Fatalf("%v: exit=%d client-called=%t", args, code, called)
		}
	}
}

func TestRunHelpExitsZero(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"run", "--help"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	help := out.String()
	if !strings.Contains(help, "usage: rsbx run") || !strings.Contains(help, "shell") {
		t.Fatalf("unexpected help: %q", out.String())
	}
	for _, expected := range []string{
		"[PATH...]", "--kit FILE", "--deny-write PATH", "HOST_IP:]HOST_PORT", "tcp6|udp6",
		"cloud sandboxes and remote/OCI kits are not supported", "it reuses automatically",
		"Agent arguments after -- are passed to the agent", "rsbx run --new --name clean-shell --detach shell",
	} {
		if !strings.Contains(help, expected) {
			t.Errorf("run help omitted %q: %q", expected, help)
		}
	}
}

func TestRunRejectsMissingAgentWithoutName(t *testing.T) {
	called := false
	runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
		called = true
		return runClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"run"}); code != 2 || called {
		t.Fatalf("exit=%d client-called=%t", code, called)
	}
}

func TestRunGeneratesUniqueNameForNewSandbox(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	want := "shell-" + sanitizeNameBase(workspace)
	if sandboxes.createCalls != 1 || sandboxes.created.Name != want {
		t.Fatalf("unexpected generated name: %q, want %q", sandboxes.created.Name, want)
	}
}

func TestRunFallsBackToHexNameWhenDerivedNameTaken(t *testing.T) {
	workspace := t.TempDir()
	taken := "shell-" + sanitizeNameBase(workspace)
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: taken, State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--new", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.createCalls != 1 {
		t.Fatalf("create=%d", sandboxes.createCalls)
	}
	name := sandboxes.created.Name
	if name == taken || !strings.HasPrefix(name, "shell-") {
		t.Fatalf("unexpected fresh name: %q", name)
	}
}

func TestRunReusesDerivedSandboxWithoutTerminal(t *testing.T) {
	workspace := t.TempDir()
	derived := "shell-" + sanitizeNameBase(workspace)
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: derived, State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, _, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "shell", workspace}); code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if sandboxes.createCalls != 0 {
		t.Fatalf("create=%d, want reuse", sandboxes.createCalls)
	}
	if !sessions.opened || sessions.req.SandboxID != "sb-old" {
		t.Fatalf("session: %+v", sessions.req)
	}
}

func TestRunNewSkipsDerivedReuse(t *testing.T) {
	workspace := t.TempDir()
	derived := "shell-" + sanitizeNameBase(workspace)
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: derived, State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--new", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.createCalls != 1 || sandboxes.created.Name == derived {
		t.Fatalf("create=%d name=%q", sandboxes.createCalls, sandboxes.created.Name)
	}
}

func TestRunUnknownFlagUsesSharedErrorContract(t *testing.T) {
	runner, _, stderr := runTestRunner(t, runClient{}, "")
	if code := runner.Run(context.Background(), []string{"run", "--bogus", "shell", "."}); code != 1 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "error: unknown flag: --bogus") || !strings.Contains(stderr.String(), "  try: rsbx run --help") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunRefusesToIgnoreDifferentWorkspaceOnReuse(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateRunning, Workspace: first}}}
	sessions := &fakeSessions{}
	runner, _, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "dev", "shell", second}); code != 1 || sessions.opened {
		t.Fatalf("exit=%d opened=%t stderr=%q", code, sessions.opened, stderr.String())
	}
	if !strings.Contains(stderr.String(), "refusing to ignore") {
		t.Fatalf("unexpected error: %q", stderr.String())
	}
}

func TestRunDetachStartsStoppedReusedSandbox(t *testing.T) {
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateStopped}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--detach", "--name", "dev"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.startCalls != 1 || sessions.opened || strings.TrimSpace(out.String()) != "sb-old" {
		t.Fatalf("start=%d opened=%t stdout=%q", sandboxes.startCalls, sessions.opened, out.String())
	}
}

func TestRunPassesEnvToSession(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "run.env")
	if err := os.WriteFile(envFile, []byte("FROM_FILE=file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "dev", "--env-file", envFile, "-e", "A=1", "--", "-c", "true"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if want := []string{"FROM_FILE=file", "A=1"}; !reflect.DeepEqual(sessions.req.Env, want) {
		t.Fatalf("env=%q want %q", sessions.req.Env, want)
	}
}

func TestRunRemovesSandboxAfterSessionWithRM(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--rm", "--name", "dev", "--", "-c", "true"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.deleteCalls != 1 || sandboxes.deleteID != "sb-old" {
		t.Fatalf("delete calls=%d id=%q", sandboxes.deleteCalls, sandboxes.deleteID)
	}
}

func TestRunRMReportsRemovalFailure(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateRunning, Workspace: workspace}}, deleteErr: errors.New("delete failed")}
	sessions := &fakeSessions{}
	runner, _, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--rm", "--name", "dev", "--", "-c", "true"}); code != 1 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "delete failed") || sandboxes.deleteCalls != 1 {
		t.Fatalf("unexpected failure: calls=%d stderr=%q", sandboxes.deleteCalls, stderr.String())
	}
}

func TestRunCreatesMultipleWorkspaces(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "multi", "shell", first, second + ":ro"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if len(sandboxes.created.Workspaces) != 2 {
		t.Fatalf("workspaces=%+v", sandboxes.created.Workspaces)
	}
	if sandboxes.created.Workspaces[0].Path != first || sandboxes.created.Workspaces[0].ReadOnly {
		t.Fatalf("first workspace=%+v", sandboxes.created.Workspaces[0])
	}
	if sandboxes.created.Workspaces[1].Path != second || !sandboxes.created.Workspaces[1].ReadOnly {
		t.Fatalf("second workspace=%+v", sandboxes.created.Workspaces[1])
	}
	if sandboxes.created.Workspace != first {
		t.Fatalf("compat workspace=%q", sandboxes.created.Workspace)
	}
	if sandboxes.created.Agent != shellAgent || sandboxes.created.Detached {
		t.Fatalf("agent/detached=%q/%t", sandboxes.created.Agent, sandboxes.created.Detached)
	}
}

func TestRunBakesEnvOnCreate(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "env-run", "-e", "A=1", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.created.Env["A"] != "1" {
		t.Fatalf("create env=%v", sandboxes.created.Env)
	}
}

func TestRunPassesProxyReferenceOnlyAsNonSecretCreateMetadata(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	proxyRef := "${proxy:openai}"
	if code := runner.Run(context.Background(), []string{"run", "--name", "proxy-run", "-e", "OPENAI_API_KEY=" + proxyRef, "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.created.Env["OPENAI_API_KEY"] != proxyRef {
		t.Fatalf("create request omitted proxy setup reference: %v", sandboxes.created.Env)
	}
	if len(sessions.req.Env) != 1 || sessions.req.Env[0] != "OPENAI_API_KEY="+proxyRef {
		t.Fatalf("exec environment=%v", sessions.req.Env)
	}
}

func TestRunDenyWriteAddsReadOnlyWorkspace(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "deny", "--deny-write", workspace, "shell"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if len(sandboxes.created.Workspaces) != 1 || !sandboxes.created.Workspaces[0].ReadOnly {
		t.Fatalf("workspaces=%+v", sandboxes.created.Workspaces)
	}
}

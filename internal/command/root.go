// Package command implements the CLI command tree.
package command

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gdamore/tcell/v3"
	"golang.org/x/term"

	sdk "github.com/rheic/sandboxes-go-sdk"

	"github.com/rheic/sandboxes-cli/internal/kit"
)

const (
	answerShortYes = "y"
	answerYes      = "yes"

	actionAllow       = "allow"
	actionDeny        = "deny"
	commandCreate     = "create"
	commandExec       = "exec"
	commandRun        = "run"
	envArgFlag        = "--env-arg"
	envArgsFileFlag   = "--env-args-file"
	workspaceLabel    = "workspace"
	commandGet        = "get"
	commandInspect    = "inspect"
	commandReset      = "reset"
	stateUnavailable  = "unavailable"
	commandAgents     = "agents"
	commandList       = "list"
	commandDelete     = "delete"
	commandRemove     = "remove"
	commandUnset      = "unset"
	commandSet        = "set"
	commandSetCustom  = "set-custom"
	schemeHTTPS       = "https"
	reasonDefaultDeny = "default deny"
)

const createUsage = `usage: rsbx create [AGENT] [PATH...] [--name NAME] [flags]

Create a sandbox for an agent. Use ` + "`rsbx agents`" + ` to list launchable built-in
agents and their pinned images. Omit PATH for no workspace mount.

Flags:
  --name NAME                 sandbox name
  --workspace PATH[:ro]       additional workspace (repeatable)
  -p, --publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6]
                              publish a TCP/UDP guest port (repeatable)
  --allow-network CIDR[:PORT] allow egress (repeatable)
  --deny-network CIDR[:PORT]  deny egress (repeatable)
  -t, --template REF          container image to use for the sandbox
  --image REF                 image override
  --kit FILE                  apply a local kit definition
  --deny-write PATH           mount PATH read-only (repeatable)
  --cpus N                    CPU count for a new sandbox
  --memory SIZE               memory limit (binary units)
  --docker                    run the dedicated Docker profile
  --idempotency-key KEY       idempotency key
  -e, --env KEY=VALUE         environment for every process (repeatable)
  --env-file FILE             read environment overrides from a file (repeatable)
`

const removeUsage = `usage: rsbx rm [-f|--force] [--format table|json|yaml] SANDBOX... | --all

Remove one or more sandboxes. --force skips confirmation and allows removal of
a running sandbox. --all removes every sandbox.
`

const pruneUsage = `usage: rsbx prune [--dry-run] [-f|--force] [--filter until=TIMESTAMP] [--format table|json|yaml]

Remove stopped sandboxes. --dry-run lists candidates without removing them;
--force skips confirmation.
`

// Runner executes commands against a local daemon.
type Runner struct {
	Out          io.Writer
	Err          io.Writer
	In           io.Reader
	Socket       string
	NewClient    func(address string) (sdk.Client, error)
	SecretScreen func() tcell.Screen
}

// NewRunner creates a CLI runner.
func NewRunner(out, errOut io.Writer) *Runner {
	return &Runner{
		Out:       out,
		Err:       errOut,
		In:        os.Stdin,
		Socket:    defaultSocket(),
		NewClient: func(address string) (sdk.Client, error) { return sdk.New(sdk.Config{Address: address}) },
	}
}

// Run executes the CLI.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return NewRunner(stdout, stderr).Run(ctx, args)
}

// Run executes the command tree and returns a process exit code.
func (r *Runner) Run(ctx context.Context, args []string) int {
	global := flag.NewFlagSet("rsbx", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	socket := global.String("socket", r.Socket, "local daemon endpoint")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			r.usage()
			return 0
		}
		return r.flagParseFailure("", err)
	}
	r.Socket = *socket
	rest := global.Args()
	if len(rest) == 0 {
		r.usage()
		return 2
	}
	if code, handled := r.runAuxiliaryCommand(ctx, rest[0], rest[1:]); handled {
		return code
	}

	switch rest[0] {
	case helpCommand, helpShort, helpFlag:
		r.usage()
		return 0
	case "version":
		return r.version(ctx, rest[1:])
	case commandCreate:
		return r.create(ctx, rest[1:])
	case "ls", commandList:
		return r.list(ctx, rest[1:])
	case commandGet:
		return r.get(ctx, rest[1:])
	case startCommand:
		return r.start(ctx, rest[1:])
	case stopCommand:
		return r.stop(ctx, rest[1:])
	case "rm", commandDelete:
		return r.remove(ctx, rest[1:])
	case "wait":
		return r.wait(ctx, rest[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "unknown command: %s\n", rest[0])
		r.usage()
		return 2
	}
}

// flagParseFailure normalizes stdlib flag parse errors to the shared CLI
// error contract: unknown flags exit 1 with a Cobra-style hint, other parse
// failures exit 2. Callers handle flag.ErrHelp before invoking it.
func (r *Runner) flagParseFailure(cmdPath string, err error) int {
	message := err.Error()
	if name, ok := strings.CutPrefix(message, "flag provided but not defined: -"); ok {
		_, _ = fmt.Fprintf(r.Err, "error: unknown flag: --%s\n  try: rsbx %s--help\n", name, commandHintPath(cmdPath))
		return 1
	}
	_, _ = fmt.Fprintf(r.Err, "error: %s\n  try: rsbx %s--help\n", message, commandHintPath(cmdPath))
	return 2
}

func commandHintPath(cmdPath string) string {
	if cmdPath == "" {
		return ""
	}
	return cmdPath + " "
}

//nolint:cyclop,gocyclo // one dispatch switch is the command router.
func (r *Runner) runAuxiliaryCommand(ctx context.Context, name string, args []string) (int, bool) {
	switch name {
	case commandRun:
		return r.run(ctx, args), true
	case "attach":
		return r.attach(ctx, args), true
	case commandExec:
		return r.exec(ctx, args), true
	case "cp":
		return r.cp(ctx, args), true
	case "login":
		return r.accountLogin(ctx, args), true
	case "logout":
		return r.accountLogout(ctx, args), true
	case secretCommand, "secrets":
		return r.secret(ctx, args), true
	case "prune":
		return r.prune(ctx, args), true
	case "diagnose":
		return r.diagnose(ctx, args), true
	case "ports":
		return r.ports(ctx, args), true
	case policyCommand:
		return r.policy(ctx, args), true
	case "settings":
		return r.settings(args), true
	case "kit":
		return r.kit(args), true
	case "daemon":
		return r.daemon(args), true
	case "template":
		return r.template(args), true
	case commandAgents:
		return r.agents(args), true
	case "env":
		return r.environment(ctx, args), true
	case commandReset:
		return r.reset(ctx, args), true
	case "tui":
		return r.tui(ctx, args), true
	case "volume", "mcp", "move", "ttl", "setup", "skills":
		return r.unsupportedFamily(name), true
	case completionCommand:
		return r.completion(args), true
	default:
		return 0, false
	}
}

func (r *Runner) accountLogin(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "Description:")
		_, _ = fmt.Fprintln(fs.Output(), "  Sign in to Docker")
		_, _ = fmt.Fprintln(fs.Output(), "\nUsage:")
		_, _ = fmt.Fprintln(fs.Output(), "  rsbx login [flags]")
		_, _ = fmt.Fprintln(fs.Output(), "\nExamples:")
		_, _ = fmt.Fprintln(fs.Output(), "  rsbx login")
		_, _ = fmt.Fprintln(fs.Output(), "\n  # Non-interactive sign-in, for CI")
		_, _ = fmt.Fprintln(fs.Output(), "  echo \"$DOCKER_PAT\" | rsbx login --username me --password-stdin")
		_, _ = fmt.Fprintln(fs.Output(), "\nFlags:")
		_, _ = fmt.Fprintln(fs.Output(), "  -h, --help              help for login")
		_, _ = fmt.Fprintln(fs.Output(), "      --password-stdin    Read password or access token from stdin")
		_, _ = fmt.Fprintln(fs.Output(), "      --username string   Docker username for non-interactive login")
	}
	username := fs.String("username", "", "Docker Hub username for PAT login")
	passwordStdin := fs.Bool("password-stdin", false, "read Docker Hub password or PAT from stdin")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("login", err)
	}
	if fs.NArg() != 0 || (*username == "") != !*passwordStdin {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx login [--username USER --password-stdin]")
		return 2
	}
	var password []byte
	if *passwordStdin {
		var err error
		password, err = readDockerPassword(r.In)
		if err != nil {
			r.error(err)
			return 2
		}
		defer clear(password)
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if *passwordStdin {
		if err := sdk.DockerPATAccounts(client).LoginWithPAT(ctx, *username, password); err != nil {
			r.error(err)
			return 1
		}
		_, _ = fmt.Fprintln(r.Out, "Logged in to Docker account")
		return 0
	}
	if err := sdk.InteractiveAccounts(client).LoginInteractive(ctx, "docker", func(ctx context.Context, info sdk.DeviceLoginInfo) error {
		return r.waitForDeviceLoginHandoff(ctx, info)
	}); err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintln(r.Out, "Logged in to Docker account")
	return 0
}

func (r *Runner) waitForDeviceLoginHandoff(ctx context.Context, info sdk.DeviceLoginInfo) error {
	if r.In == nil {
		return errors.New("interactive login input is unavailable")
	}
	if _, err := fmt.Fprintf(r.Err, "Docker verification code: %s\nPress Enter to open %s, or Ctrl-C to cancel.\nIf the browser does not open, visit the URL above and enter the code.\n", info.UserCode, info.VerificationURI); err != nil {
		return errors.New("write Docker device authorization details failed")
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := bufio.NewReader(r.In).ReadString('\n')
		readDone <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-readDone:
		if err != nil {
			return errors.New("docker device login canceled before authorization handoff")
		}
		if _, err := fmt.Fprintln(r.Err, "Waiting for Docker authorization..."); err != nil {
			return errors.New("write Docker authorization status failed")
		}
		return nil
	}
}

func readDockerPassword(input io.Reader) ([]byte, error) {
	if input == nil {
		return nil, errors.New("password stdin is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 2049))
	if err != nil {
		clear(raw)
		return nil, errors.New("read Docker Hub password from stdin failed")
	}
	defer clear(raw)
	if len(raw) > 2048 {
		return nil, errors.New("password exceeds 2048 bytes for Docker Hub")
	}
	end := len(raw)
	if end > 0 && raw[end-1] == '\n' {
		end--
		if end > 0 && raw[end-1] == '\r' {
			end--
		}
	}
	password := raw[:end]
	if len(password) == 0 || bytes.ContainsAny(password, "\r\n\x00") {
		return nil, errors.New("stdin must contain one non-empty Docker Hub password line")
	}
	return append([]byte(nil), password...), nil
}

func (r *Runner) accountLogout(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "Description:")
		_, _ = fmt.Fprintln(fs.Output(), "  Stop running local sandboxes and sign out of Docker")
		_, _ = fmt.Fprintln(fs.Output(), "\nUsage:")
		_, _ = fmt.Fprintln(fs.Output(), "  rsbx logout [flags]")
		_, _ = fmt.Fprintln(fs.Output(), "\nExamples:")
		_, _ = fmt.Fprintln(fs.Output(), "  rsbx logout")
		_, _ = fmt.Fprintln(fs.Output(), "\n  # Skip the confirmation prompt")
		_, _ = fmt.Fprintln(fs.Output(), "  rsbx logout --force")
		_, _ = fmt.Fprintln(fs.Output(), "\nFlags:")
		_, _ = fmt.Fprintln(fs.Output(), "  -f, --force   Skip confirmation prompt")
		_, _ = fmt.Fprintln(fs.Output(), "  -h, --help    help for logout")
	}
	force := fs.Bool("force", false, "skip confirmation")
	forceShort := fs.Bool("f", false, "skip confirmation")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("logout", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx logout [--force]")
		return 2
	}
	if !*force && !*forceShort {
		confirmed, err := r.confirmLogout()
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "Logout canceled")
			return 0
		}
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	stopped, err := r.stopRunningSandboxes(ctx, client)
	if err != nil {
		r.error(err)
		return 1
	}
	removed, err := sdk.Accounts(client).Logout(ctx, "docker")
	if err != nil {
		r.error(err)
		return 1
	}
	if removed {
		_, _ = fmt.Fprintln(r.Out, "Removed local Docker account credentials")
	} else {
		_, _ = fmt.Fprintln(r.Out, "No local Docker account credentials found")
	}
	if stopped > 0 {
		_, _ = fmt.Fprintf(r.Out, "Stopped %d running local sandbox(es)\n", stopped)
	}
	return 0
}

func (r *Runner) confirmLogout() (bool, error) {
	file, ok := r.In.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return false, fmt.Errorf("logout confirmation requires a terminal; use --force to skip confirmation")
	}
	if _, err := fmt.Fprint(r.Err, "Stop running local sandboxes and sign out? [y/N] "); err != nil {
		return false, fmt.Errorf("write logout prompt: %w", err)
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read logout confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == answerShortYes || answer == answerYes, nil
}

func (r *Runner) stopRunningSandboxes(ctx context.Context, client sdk.Client) (int, error) {
	stopped, seenPages := 0, make(map[string]struct{})
	token := ""
	for pages := 0; pages < 10000; pages++ {
		page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: 100, PageToken: token})
		if err != nil {
			return stopped, fmt.Errorf("list local sandboxes before logout: %w", err)
		}
		pageCount, err := r.stopSandboxesOnPage(ctx, client, page.Items)
		stopped += pageCount
		if err != nil {
			return stopped, err
		}
		if page.NextPageToken == "" {
			return stopped, nil
		}
		if _, ok := seenPages[page.NextPageToken]; ok {
			return stopped, fmt.Errorf("daemon returned a repeated sandbox page token")
		}
		seenPages[page.NextPageToken] = struct{}{}
		token = page.NextPageToken
	}
	return stopped, fmt.Errorf("daemon returned too many sandbox pages")
}

func (r *Runner) stopSandboxesOnPage(ctx context.Context, client sdk.Client, items []sdk.Sandbox) (int, error) {
	stopped := 0
	for i := range items {
		sandbox := &items[i]
		if sandbox.State != sdk.StateRunning {
			continue
		}
		if err := r.stopSandbox(ctx, client, sandbox); err != nil {
			return stopped, err
		}
		stopped++
	}
	return stopped, nil
}

func (r *Runner) stopSandbox(ctx context.Context, client sdk.Client, sandbox *sdk.Sandbox) error {
	op, err := client.Sandboxes().Stop(ctx, sandbox.ID, sdk.StopOptions{})
	if err != nil {
		return fmt.Errorf("stop sandbox %s before logout: %w", sandbox.Name, err)
	}
	if op == nil || op.ID == "" {
		return nil
	}
	completed, err := client.Operations().Wait(ctx, op.ID)
	if err != nil {
		return fmt.Errorf("wait for sandbox %s to stop: %w", sandbox.Name, err)
	}
	if completed != nil && completed.State == sdk.StateFailed {
		return fmt.Errorf("sandbox %s failed to stop", sandbox.Name)
	}
	return nil
}

func (r *Runner) secret(ctx context.Context, args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx secret <import|set|ls|list|rm|remove|delete|unset> [flags]")
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		return r.secretHelp()
	case commandSet:
		return r.secretSetCommand(ctx, args[1:])
	case "rm", commandRemove, commandDelete, commandUnset:
		return r.secretRemoveCommand(ctx, args[1:])
	case "ls", commandList:
		if hasFlag(args[1:], "--help") || hasFlag(args[1:], "-h") {
			return r.secretListHelp()
		}
		return r.serviceSecretList(ctx, args[1:])
	case "import", commandSetCustom:
		return r.secretExtendedCommand(ctx, args)
	default:
		_, _ = fmt.Fprintln(r.Err, "unknown secret command")
		return 2
	}
}

func (r *Runner) secretHelp() int {
	_, _ = fmt.Fprintln(r.Out, "usage: rsbx secret <import|set|ls|list|rm|remove|delete|unset> [flags]")
	_, _ = fmt.Fprintln(r.Out, "commands: import, ls (alias: list), set, rm (aliases: remove, delete, unset; service secrets and registry credentials)")
	_, _ = fmt.Fprintln(r.Out, "set-custom is not implemented; custom secret values are never stored or injected")
	return 0
}

func (r *Runner) secretSetCommand(ctx context.Context, args []string) int {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		return r.secretSetHelp()
	}
	if hasFlag(args, registryFlag) {
		return r.registrySet(ctx, args)
	}
	return r.serviceSecretSet(ctx, args)
}

func (r *Runner) secretRemoveCommand(ctx context.Context, args []string) int {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		return r.secretRemoveHelp()
	}
	if hasFlag(args, "--all") && hasFlag(args, globalFlag) {
		_, _ = fmt.Fprintln(r.Err, "error: if any flags in the group [all global] are set none of the others can be; [all global] were all set\n  try: rsbx secret rm --help")
		return 1
	}
	if hasFlag(args, "--all") {
		return r.serviceSecretRemoveAll(ctx, args)
	}
	if hasFlag(args, "--all-sandboxes") && !hasFlag(args, registryFlag) {
		_, _ = fmt.Fprintln(r.Err, "error: --all-sandboxes requires --registry\n  try: rsbx secret rm --help")
		return 1
	}
	if hasFlag(args, registryFlag) || hasFlag(args, "--all-sandboxes") {
		return r.registryRemove(ctx, args)
	}
	return r.serviceSecretRemove(ctx, args)
}

func (r *Runner) secretExtendedCommand(ctx context.Context, args []string) int {
	if args[0] == commandSetCustom {
		if hasFlag(args[1:], "--help") || hasFlag(args[1:], "-h") {
			return r.secretCustomHelp()
		}
		_, _ = fmt.Fprintln(r.Err, "rsbx secret set-custom: unsupported: custom secret storage and proxy substitution are not implemented; no secret was stored")
		return 1
	}
	if hasFlag(args[1:], "--help") || hasFlag(args[1:], "-h") {
		return r.secretImportHelp()
	}
	return r.serviceSecretImport(ctx, args[1:])
}

func (r *Runner) secretCustomHelp() int {
	const usage = `Description:
  Docker sbx supports custom secrets by storing a placeholder in the sandbox and
  replacing it in matching outbound request headers. Rheic does not implement
  custom-secret storage or proxy substitution yet.

Status:
  Unsupported. This command will not store or inject a secret.

Usage:
  rsbx secret set-custom [flags]

Docker sbx option families include --host, --env, --name, --placeholder,
--header, --format, --value, --token, --ref, --command, --sandbox, and --refresh.
Passing these options to Rheic currently fails closed.
`
	if _, err := io.WriteString(r.Out, usage); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) secretSetHelp() int {
	const usage = `Description:
  Create or update a service secret or registry credential.

Available services:
  anthropic, copilot, cursor, devin, droid, github, google, groq, mistral,
  nebius, openai, openrouter, xai

Usage:
  rsbx secret set [SERVICE] [flags]

When SERVICE is omitted, choose it with the arrow keys and Enter. Press q or
Escape to cancel. Values are stored in the host credential vault. Without
--force, an existing value is never overwritten. For scripts, pass SERVICE
explicitly and provide the value with --token or standard input.

Registry credentials
  Use --registry to store a registry credential. Without --sandbox or
  --all-sandboxes, it is host-only and is not injected into sandboxes.
  --all-sandboxes enables brokered use in all sandboxes; --sandbox scopes it
  to one sandbox. Credentials are provided to the host broker, not guest env.
  Cross-host registry authentication endpoints are not supported yet.

Examples:
  rsbx secret set github
  rsbx secret set openai --sandbox my-sandbox
  rsbx secret set openai --oauth
  rsbx secret set github -t VALUE
  printf '%s' "$GHCR_TOKEN" | rsbx secret set --registry ghcr.io \
    --username USER --password-stdin
  printf '%s' "$GHCR_TOKEN" | rsbx secret set --registry ghcr.io \
    --username USER --password-stdin --all-sandboxes

Flags:
      --sandbox string  Scope the secret to one sandbox
  -t, --token string   Secret value (less secure: visible in shell history)
      --oauth           Sign in to the global OpenAI account on the host
      --ref string      Use a 1Password op:// reference or AWS Secrets Manager ARN
      --command string  Run a host shell command to resolve a secret (can access host files)
      --refresh string  Refresh source on-demand or after a duration (default: 55m)
      --no-verify       Store a source without resolving it now
      --show-error      Show provider stderr on initial verification failure (may contain secrets)
      --registry string Registry hostname for pull credentials
      --username string Registry username
      --password-stdin Read registry password or token from stdin
      --all-sandboxes   Enable brokered registry use in every sandbox
  -f, --force           Overwrite an existing secret
  -h, --help            Show this help
`
	if _, err := io.WriteString(r.Out, usage); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) secretRemoveHelp() int {
	const usage = `Description:
  Remove a service or registry credential.

Usage:
  rsbx secret rm [SERVICE] [flags]
  rsbx secret rm --registry HOST [flags]
  rsbx secret rm --all [--force]

Aliases:
  rm, remove, delete, unset

Examples:
  rsbx secret rm
  rsbx secret rm openai
  rsbx secret rm openai --sandbox my-sandbox
  rsbx secret rm openai --oauth
  rsbx secret rm --registry ghcr.io --all-sandboxes --force

Flags:
      --oauth             Remove host-side OpenAI OAuth credentials
      --all               Remove inventoried Rheic credentials across scopes
      --registry string   Registry hostname; without a scope flag removes host-only and all-sandboxes credentials
      --all-sandboxes     Remove the all-sandboxes registry credential (requires --registry)
      --sandbox string    Scope service or registry credentials to one sandbox
  -f, --force             Delete without confirmation prompt
  -h, --help              Show this help
`
	if _, err := io.WriteString(r.Out, usage); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) secretListHelp() int {
	const usage = `Description:
  List stored secrets across global and sandbox scopes. Secret values are never
  displayed. Use --global or --sandbox to limit the inventory, and --service to
  filter by provider.

Usage:
  rsbx secret ls [flags]

Aliases:
  ls, list

Examples:
  rsbx secret ls
  rsbx secret ls -g
  rsbx secret ls --sandbox my-sandbox
  rsbx secret ls --service github
  rsbx secret ls --json

Flags:
      --format string   Output format: table, json or yaml
  -g, --global          Only list global secrets
  -h, --help            Show this help
      --json            Output in JSON format
  -q, --quiet           Only display secret names
      --sandbox string  Only list secrets scoped to one sandbox
      --service string  Filter by secret service name
`
	if _, err := io.WriteString(r.Out, usage); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) serviceSecretRemoveAll(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("secret rm", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	all := fs.Bool("all", false, "remove inventoried host credentials")
	force := fs.Bool("force", false, "delete without confirmation prompt")
	fs.BoolVar(force, "f", false, "delete without confirmation prompt")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("secret rm", err)
	}
	if !*all || fs.NArg() != 0 {
		if *all && fs.NArg() != 0 {
			_, _ = fmt.Fprintln(r.Err, "error: cannot specify a SERVICE argument when using --all\n  try: rsbx secret rm --help")
			return 1
		}
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx secret rm --all [--force]")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	inventory, err := loadSecretRemovalInventory(ctx, client)
	if err != nil {
		r.error(err)
		return 1
	}
	confirmed, code := r.confirmSecretRemoval(fmt.Sprintf("all %d inventoried host credentials", inventory.count()), *force)
	if code != 0 {
		return code
	}
	if !confirmed {
		return 0
	}
	removed, err := removeSecretRemovalInventory(ctx, client, inventory)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Removed %d inventoried Rheic-managed host credentials\n", removed)
	_, _ = fmt.Fprintln(r.Out, "Custom-secret storage is unavailable and was not included.")
	return 0
}

type secretRemovalInventory struct {
	services   []sdk.ServiceSecret
	registries []sdk.RegistryCredentialSummary
	accounts   []string
}

func (i secretRemovalInventory) count() int {
	return len(i.services) + len(i.registries) + len(i.accounts)
}

func loadSecretRemovalInventory(ctx context.Context, client sdk.Client) (secretRemovalInventory, error) {
	services, err := sdk.Secrets(client).List(ctx)
	if err != nil {
		return secretRemovalInventory{}, fmt.Errorf("list service credentials before removal: %w", err)
	}
	registryLister, ok := sdk.RegistryCredentialList(client)
	if !ok {
		return secretRemovalInventory{}, errors.New("this client cannot list registry credentials; refusing incomplete --all removal")
	}
	registries, err := registryLister.ListRegistryCredentials(ctx)
	if err != nil {
		return secretRemovalInventory{}, fmt.Errorf("list registry credentials before removal: %w", err)
	}
	inventory := secretRemovalInventory{services: services, registries: registries}
	for _, provider := range []string{"docker", openAIService} {
		present, err := sdk.AccountStatus(client).Status(ctx, provider)
		if err != nil {
			return secretRemovalInventory{}, fmt.Errorf("check %s account credentials before removal: %w", provider, err)
		}
		if present {
			inventory.accounts = append(inventory.accounts, provider)
		}
	}
	return inventory, nil
}

func removeSecretRemovalInventory(ctx context.Context, client sdk.Client, inventory secretRemovalInventory) (int, error) {
	removed, err := removeServiceSecretInventory(ctx, sdk.Secrets(client), inventory.services)
	if err != nil {
		return removed, err
	}
	removed, err = removeRegistrySecretInventory(ctx, client.RegistryCredentials(), inventory.registries, removed)
	if err != nil {
		return removed, err
	}
	return removeAccountInventory(ctx, sdk.Accounts(client), inventory.accounts, removed)
}

func removeServiceSecretInventory(ctx context.Context, secrets sdk.SecretService, items []sdk.ServiceSecret) (int, error) {
	removed := 0
	for _, item := range items {
		ok, err := secrets.Remove(ctx, item.Service, item.Scope, item.SandboxName)
		if err != nil {
			return removed, fmt.Errorf("partial credential removal after %d entries: %w", removed, err)
		}
		if ok {
			removed++
		}
	}
	return removed, nil
}

func removeRegistrySecretInventory(ctx context.Context, registries sdk.RegistryCredentialService, items []sdk.RegistryCredentialSummary, removed int) (int, error) {
	for _, item := range items {
		response, err := registries.Logout(ctx, sdk.RegistryLogoutRequest{
			Registry: item.Registry, Scope: sdk.RegistryCredentialScope(item.Scope), SandboxName: item.SandboxName,
		})
		if err != nil {
			return removed, fmt.Errorf("partial credential removal after %d entries: %w", removed, err)
		}
		if response != nil && response.Removed {
			removed++
		}
	}
	return removed, nil
}

func removeAccountInventory(ctx context.Context, accounts sdk.AccountService, providers []string, removed int) (int, error) {
	for _, provider := range providers {
		ok, err := accounts.Logout(ctx, provider)
		if err != nil {
			return removed, fmt.Errorf("partial credential removal after %d entries: %w", removed, err)
		}
		if ok {
			removed++
		}
	}
	return removed, nil
}

// reorderFlagArgs moves flags and their values before positionals so the
// standard library flag parser accepts the Docker sbx flag-after-argument
// grammar. It never interprets values as flags.
func reorderFlagArgs(args []string, valueFlags map[string]bool) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		flags = append(flags, arg)
		name, _, hasValue := strings.Cut(arg, "=")
		if hasValue {
			continue
		}
		if valueFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}

func (r *Runner) unsupportedFamily(name string) int {
	reasons := map[string]string{
		"volume": "persistent volumes are cloud-only in this build",
		"mcp":    "the MCP gateway is not implemented",
		"move":   "cloud move is unavailable without a tenant",
		"ttl":    "cloud TTL is unavailable without a tenant",
		"setup":  "host setup is not implemented",
		"skills": "skills management is not implemented",
	}
	_, _ = fmt.Fprintf(r.Err, "rsbx %s: unsupported: %s\n", name, reasons[name])
	return 1
}

func hasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == name || strings.HasPrefix(arg, name+"=") {
			return true
		}
		if arg == "--" {
			return false
		}
	}
	return false
}

func (r *Runner) confirmSecretRemoval(target string, force bool) (bool, int) {
	if force {
		return true, 0
	}
	input, ok := r.In.(*os.File)
	if !ok || !term.IsTerminal(int(input.Fd())) {
		_, _ = fmt.Fprintln(r.Err, "error: stdin is not a terminal; use --force to skip confirmation")
		return false, 1
	}
	if _, err := fmt.Fprintf(r.Err, "Remove %s? [y/N] ", sanitizeTerminalText(target)); err != nil {
		r.error(err)
		return false, 1
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && answer == "" {
		r.error(errors.New("could not read confirmation"))
		return false, 1
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, 0
	default:
		_, _ = fmt.Fprintln(r.Err, "Removal canceled")
		return false, 0
	}
}

func (r *Runner) registryRemove(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{registryFlag: true, sandboxFlag: true, "--all-sandboxes": false, globalFlag: false, forceFlag: false, "-f": false})
	fs := flag.NewFlagSet("secret rm", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	registry := fs.String("registry", "", "registry host")
	allSandboxes := fs.Bool("all-sandboxes", false, "remove all-sandboxes credential")
	sandboxName := fs.String("sandbox", "", "remove credential for one sandbox")
	global := fs.Bool("global", false, "deprecated: remove global credential")
	force := fs.Bool("force", false, "delete without confirmation prompt")
	fs.BoolVar(force, "f", false, "delete without confirmation prompt")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("secret rm", err)
	}
	if message, code := registryRemovalArgumentError(*registry, fs.NArg(), *sandboxName, *global, *allSandboxes); code != 0 {
		_, _ = fmt.Fprintln(r.Err, message)
		return code
	}
	if fs.NArg() == 1 {
		*sandboxName = fs.Arg(0)
		_, _ = fmt.Fprintf(r.Err, "warning: the positional sandbox scope is deprecated and will be removed in a future release; use --sandbox %s with --registry\n", sanitizeTerminalText(*sandboxName))
	}
	if *global {
		_, _ = fmt.Fprintln(r.Err, "warning: --global is deprecated; global is now the default for service secrets; omit --global, use --sandbox to target one sandbox, or use --all-sandboxes with --registry")
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	scopes := registryRemovalScopes(*sandboxName, *global, *allSandboxes)
	lister, ok := sdk.RegistryCredentialList(client)
	if !ok {
		r.error(errors.New("registry credential inventory is unavailable; refusing removal before confirmation"))
		return 1
	}
	items, err := lister.ListRegistryCredentials(ctx)
	if err != nil {
		r.error(fmt.Errorf("list registry credentials before removal: %w", err))
		return 1
	}
	if !registryCredentialPresent(items, *registry, *sandboxName, scopes) {
		scopeName := registryRemovalScopeName(*sandboxName, *allSandboxes)
		_, _ = fmt.Fprintf(r.Err, "error: no registry secret found for %q in scope %q\n", *registry, scopeName)
		return 1
	}
	confirmed, code := r.confirmSecretRemoval(fmt.Sprintf("registry credentials for %s", *registry), *force)
	if code != 0 {
		return code
	}
	if !confirmed {
		return 0
	}
	return r.removeRegistryScopes(ctx, client, *registry, *sandboxName, scopes)
}

func registryCredentialPresent(items []sdk.RegistryCredentialSummary, registry, sandboxName string, scopes []sdk.RegistryCredentialScope) bool {
	for _, item := range items {
		if item.Registry != registry || item.SandboxName != sandboxName {
			continue
		}
		for _, scope := range scopes {
			if item.Scope == string(scope) {
				return true
			}
		}
	}
	return false
}

func registryRemovalScopeName(sandboxName string, allSandboxes bool) string {
	if sandboxName != "" {
		return sandboxName
	}
	if allSandboxes {
		return "(all-sandboxes)"
	}
	// Both explicit global and default registry removal use Docker's global label.
	return globalScopeLabel
}

func registryRemovalArgumentError(registry string, positionals int, sandboxName string, global, allSandboxes bool) (string, int) {
	if conflict := registryRemovalScopeConflict(global, allSandboxes, sandboxName != ""); conflict != "" {
		return conflict, 1
	}
	if registry == "" || positionals > 1 {
		return "usage: rsbx secret rm [--registry HOST] [--all-sandboxes | --sandbox NAME]", 2
	}
	if positionals == 1 && (sandboxName != "" || global || allSandboxes) {
		return "error: cannot combine a positional sandbox name with a scope flag\n  try: rsbx secret rm --help", 1
	}
	return "", 0
}

func registryRemovalScopes(sandboxName string, global, allSandboxes bool) []sdk.RegistryCredentialScope {
	if allSandboxes {
		return []sdk.RegistryCredentialScope{sdk.RegistryScopeAllSandboxes}
	}
	if sandboxName != "" {
		return []sdk.RegistryCredentialScope{sdk.RegistryScopeSandbox}
	}
	if global {
		return []sdk.RegistryCredentialScope{sdk.RegistryScopeHostOnly}
	}
	return []sdk.RegistryCredentialScope{sdk.RegistryScopeHostOnly, sdk.RegistryScopeAllSandboxes}
}

func registryRemovalScopeConflict(global, allSandboxes, sandbox bool) string {
	if global && allSandboxes {
		return "error: cannot specify both --global and --all-sandboxes\n  try: rsbx secret rm --help"
	}
	if sandbox && (global || allSandboxes) {
		return "error: cannot combine --sandbox with --global or --all-sandboxes\n  try: rsbx secret rm --help"
	}
	return ""
}

func (r *Runner) removeRegistryScopes(ctx context.Context, client sdk.Client, registry, sandboxName string, scopes []sdk.RegistryCredentialScope) int {
	removedAny := false
	for _, scope := range scopes {
		response, err := client.RegistryCredentials().Logout(ctx, sdk.RegistryLogoutRequest{
			Registry: registry, Scope: scope, SandboxName: sandboxName,
		})
		if err != nil {
			if removedAny {
				r.error(fmt.Errorf("partial registry credential removal for %s: %w", registry, err))
			} else {
				r.error(err)
			}
			return 1
		}
		removedAny = removedAny || response.Removed
		status := "No registry credentials stored"
		if response.Removed {
			status = "Removed registry credentials"
		}
		_, _ = fmt.Fprintf(r.Out, "%s for %s (%s)\n", status, sanitizeTerminalText(registry), scope)
	}
	return 0
}

func (r *Runner) registrySet(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("secret set", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	registry := fs.String("registry", "", "registry host")
	username := fs.String("username", "", "registry username")
	passwordStdin := fs.Bool("password-stdin", false, "read password from stdin")
	allSandboxes := fs.Bool("all-sandboxes", false, "allow future brokered use in all sandboxes")
	sandboxName := fs.String("sandbox", "", "allow future brokered use in one sandbox")
	if code, done := r.parseFlagsOrFail("secret set", fs, args); done {
		return code
	}
	if !validRegistryArguments(fs.NArg(), *registry) {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx secret set [--registry HOST] --username USER [--password-stdin] [--all-sandboxes | --sandbox NAME]")
		return 2
	}
	if *allSandboxes && *sandboxName != "" {
		_, _ = fmt.Fprintln(r.Err, "--all-sandboxes and --sandbox cannot be combined")
		return 2
	}
	if *username == "" {
		if *passwordStdin {
			_, _ = fmt.Fprintln(r.Err, "--username is required with --password-stdin")
			return 2
		}
		if _, err := fmt.Fprint(r.Err, "Username: "); err != nil {
			r.error(err)
			return 1
		}
		line, err := bufio.NewReader(r.In).ReadString('\n')
		if err != nil && line == "" {
			r.error(fmt.Errorf("read username: %w", err))
			return 1
		}
		*username = strings.TrimSpace(line)
	}
	password, err := r.readLoginPassword(*passwordStdin)
	if err != nil {
		r.error(err)
		return 2
	}
	defer clear(password)
	scope := sdk.RegistryScopeHostOnly
	if *allSandboxes {
		scope = sdk.RegistryScopeAllSandboxes
	} else if *sandboxName != "" {
		scope = sdk.RegistryScopeSandbox
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	response, err := client.RegistryCredentials().Login(ctx, sdk.RegistryLoginRequest{
		Registry: *registry, Username: *username, Password: password,
		Scope: scope, SandboxName: *sandboxName,
	})
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Credentials stored (not verified) in host keychain for %s as %s (%s); sandbox registry access is not enabled yet\n", response.Registry, response.Username, response.Scope)
	return 0
}

type flagParseError struct{ err error }

func (e flagParseError) Error() string { return e.err.Error() }

func asFlagParseError(err error) (flagParseError, bool) {
	var parseErr flagParseError
	if errors.As(err, &parseErr) {
		return parseErr, true
	}
	return flagParseError{}, false
}

// parseFlagsOrFail parses a flag set and reports failures through the shared
// error contract, returning done=true when the caller should return code.
func (r *Runner) parseFlagsOrFail(cmdPath string, fs *flag.FlagSet, args []string) (code int, done bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		return r.flagParseFailure(cmdPath, err), true
	}
	return 0, false
}

func validRegistryArguments(count int, registry string) bool {
	return count == 0 && registry != ""
}

func (r *Runner) readLoginPassword(fromStdin bool) ([]byte, error) {
	if file, ok := r.In.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		if fromStdin {
			return nil, fmt.Errorf("refusing to read --password-stdin from an interactive terminal; omit the flag for hidden prompt")
		}
		if _, err := fmt.Fprint(r.Err, "Password: "); err != nil {
			return nil, fmt.Errorf("write password prompt: %w", err)
		}
		password, err := term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(r.Err)
		if err != nil {
			return nil, fmt.Errorf("read password from terminal: %w", err)
		}
		return password, nil
	}
	if !fromStdin {
		return nil, fmt.Errorf("password input is not a terminal; use --password-stdin")
	}
	data, err := io.ReadAll(io.LimitReader(r.In, 2050))
	if err != nil {
		clear(data)
		return nil, fmt.Errorf("read password from stdin: %w", err)
	}
	if len(data) > 2049 {
		clear(data)
		return nil, fmt.Errorf("password exceeds the 2048-byte limit")
	}
	data = bytes.TrimSuffix(bytes.TrimSuffix(data, []byte("\n")), []byte("\r"))
	if len(data) == 0 || len(data) > 2048 || bytes.ContainsAny(data, "\r\n") {
		clear(data)
		return nil, fmt.Errorf("password input must contain one non-empty line up to 2048 bytes")
	}
	return data, nil
}

type createOptions struct {
	name             string
	agent            string
	image            string
	workspace        string
	idempotencyKey   string
	workspaces       []sdk.Workspace
	ports            []sdk.Port
	allow            []sdk.NetworkRule
	deny             []sdk.NetworkRule
	cpus             uint32
	memoryMiB        uint32
	env              []string
	oauthCredentials []sdk.OAuthCredential
	profile          string
	privileged       bool
}

func (r *Runner) create(ctx context.Context, args []string) int {
	opts, help, err := parseCreateOptions(ctx, args)
	if help {
		_, _ = fmt.Fprint(r.Out, createUsage)
		return 0
	}
	if parseErr, ok := asFlagParseError(err); ok {
		return r.flagParseFailure(commandCreate, parseErr.err)
	}
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	name := opts.name
	if name == "" {
		base := ""
		if len(opts.workspaces) > 0 {
			base = sanitizeNameBase(opts.workspaces[0].Path)
		}
		name, err = runSandboxName(ctx, client, "", opts.agent, base)
		if err != nil {
			r.error(err)
			return 1
		}
	}
	op, err := client.Sandboxes().Create(ctx, sdk.CreateRequest{
		Name:             name,
		Image:            opts.image,
		Workspace:        opts.workspace,
		Workspaces:       opts.workspaces,
		Ports:            opts.ports,
		Allow:            opts.allow,
		Deny:             opts.deny,
		IdempotencyKey:   opts.idempotencyKey,
		Agent:            opts.agent,
		CPUs:             opts.cpus,
		MemoryMiB:        opts.memoryMiB,
		PolicyProfile:    opts.profile,
		Privileged:       opts.privileged,
		Env:              envMap(opts.env),
		OAuthCredentials: opts.oauthCredentials,
	})
	if err != nil {
		r.error(err)
		return 1
	}
	r.printCreatedSandbox(ctx, client, name, op)
	return 0
}

// printCreatedSandbox renders the human create summary; operation records stay
// available through --format json on lifecycle commands.
func (r *Runner) printCreatedSandbox(ctx context.Context, client sdk.Client, name string, op *sdk.Operation) {
	id := ""
	if op != nil {
		id = op.SandboxID
	}
	sb, err := lookupSandboxForReport(ctx, client, id, name)
	if err != nil || sb == nil {
		_, _ = fmt.Fprintf(r.Out, "Created sandbox %s\n", name)
		return
	}
	_, _ = fmt.Fprint(r.Out, sandboxReport(sb))
	_, _ = fmt.Fprintf(r.Out, "Created sandbox %s\n", sb.Name)
}

// lookupSandboxForReport resolves a sandbox by ID first and falls back to name.
func lookupSandboxForReport(ctx context.Context, client sdk.Client, id, name string) (*sdk.Sandbox, error) {
	if id != "" {
		sb, err := client.Sandboxes().Get(ctx, id)
		if err == nil {
			return sb, nil
		}
	}
	sb, found, err := lookupSandboxByName(ctx, client, name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("sandbox %q not found", name)
	}
	return sb, nil
}

// sandboxReport formats a created sandbox like the Docker sbx baseline.
func sandboxReport(sb *sdk.Sandbox) string {
	agent := formatAgent(sb.Agent)
	return fmt.Sprintf(`
SANDBOX
  Name:       %s
  Agent:      %s
  Workspace:  %s
  Image:      %s
  CPU:        %d
  Memory:     %s

`, sb.Name, agent, formatWorkspaces(sb), sb.Image, sb.CPUs, formatMemoryMiB(sb.MemoryMiB))
}

// formatMemoryMiB renders memory sizes like the Docker sbx baseline.
func formatMemoryMiB(mib uint32) string {
	if mib == 0 {
		return "-"
	}
	if mib%1024 == 0 {
		return fmt.Sprintf("%d GiB", mib/1024)
	}
	return fmt.Sprintf("%d MiB", mib)
}

func parseCreatePositionals(positionals []string, nameFlag string) (string, string, []string, error) {
	if len(positionals) == 0 {
		return "", "", nil, errors.New("usage: rsbx create [AGENT] [PATH...] [--name NAME] [--cpus N] [--memory SIZE] [--image REF]")
	}
	agent := ""
	paths := []string(nil)
	name := nameFlag
	if isAgentName(positionals[0]) {
		agent = positionals[0]
		paths = positionals[1:]
	} else {
		if name != "" {
			return "", "", nil, errors.New("--name requires an agent argument (for example: rsbx create --name dev shell PATH)")
		}
		name = positionals[0]
		paths = positionals[1:]
	}
	if agent != "" {
		if err := validateRunAgent(agent); err != nil {
			return "", "", nil, err
		}
	}
	return name, agent, paths, nil
}

// resolveTemplateImage applies the Docker sbx baseline --template alias.
func resolveTemplateImage(image, template string) (string, error) {
	if template == "" {
		return image, nil
	}
	if image != "" {
		return "", errors.New("--template and --image cannot be combined")
	}
	return template, nil
}

func validateCreateResources(cpus uint, memory string) (uint32, uint32, error) {
	cpuCount, err := validateCPUs(cpus)
	if err != nil {
		return 0, 0, err
	}
	memoryMiB, err := parseMemoryMiB(memory)
	if err != nil {
		return 0, 0, err
	}
	return cpuCount, memoryMiB, nil
}

func resolveCreateWorkspaces(workspaceFlags stringListFlag, paths []string) ([]sdk.Workspace, error) {
	combined := make(stringListFlag, 0, len(workspaceFlags)+len(paths))
	combined = append(combined, workspaceFlags...)
	combined = append(combined, paths...)
	return resolveWorkspaces(combined, false)
}

//nolint:gocyclo,cyclop,funlen // create accepts the full documented flag matrix.
func parseCreateOptions(ctx context.Context, args []string) (createOptions, bool, error) {
	fs := flag.NewFlagSet(commandCreate, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	image := fs.String("image", "", "image reference")
	template := fs.String("template", "", "container image to use for the sandbox (alias for --image)")
	fs.StringVar(template, "t", "", "container image to use for the sandbox (alias for --image)")
	nameFlag := fs.String("name", "", "sandbox name")
	var workspaceFlags stringListFlag
	fs.Var(&workspaceFlags, workspaceLabel, "host workspace path, optionally suffixed with :ro (repeatable)")
	var publishFlags stringListFlag
	fs.Var(&publishFlags, "publish", "publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6] (repeatable)")
	fs.Var(&publishFlags, "p", "publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6] (repeatable; alias for --publish)")
	var allowFlags, denyFlags stringListFlag
	fs.Var(&allowFlags, "allow-network", "allow egress CIDR[:PORT] (repeatable; optional udp: prefix)")
	fs.Var(&denyFlags, "deny-network", "deny egress CIDR[:PORT] (repeatable; optional udp: prefix)")
	var envFlags, envFileFlags stringListFlag
	fs.Var(&envFlags, "env", "environment KEY=VALUE for every process (repeatable)")
	fs.Var(&envFlags, "e", "environment KEY=VALUE for every process (repeatable)")
	fs.Var(&envFileFlags, "env-file", "read environment from a file (repeatable)")
	idempotency := fs.String("idempotency-key", "", "idempotency key")
	cpus := fs.Uint("cpus", 0, "CPUs (0 selects the daemon default)")
	memory := fs.String("memory", "", "memory limit such as 512m or 2g (empty selects the daemon default)")
	profile := fs.String("policy-profile", "", "egress profile: deny-all, balanced or sbx-compat")
	privileged := fs.Bool("docker", false, "run the dedicated Docker profile")
	kitPath := fs.String("kit", "", "apply a local kit definition")
	var denyWriteFlags stringListFlag
	fs.Var(&denyWriteFlags, "deny-write", "mount PATH read-only (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return createOptions{}, true, nil
		}
		return createOptions{}, false, flagParseError{err: err}
	}
	positionals := fs.Args()
	if *kitPath != "" && len(positionals) == 0 {
		doc, err := kit.Load(*kitPath)
		if err != nil {
			return createOptions{}, false, err
		}
		if doc.Spec.Agent == "" {
			return createOptions{}, false, fmt.Errorf("kit %s does not define an agent", *kitPath)
		}
		positionals = []string{doc.Spec.Agent}
	}
	name, agent, paths, err := parseCreatePositionals(positionals, *nameFlag)
	if err != nil {
		return createOptions{}, false, err
	}
	imageRef, err := resolveTemplateImage(*image, *template)
	if err != nil {
		return createOptions{}, false, err
	}
	var oauthCredentials []sdk.OAuthCredential
	if *kitPath != "" {
		kitPaths := []string(workspaceFlags)
		kitEnv := []string(envFlags)
		if err := applyKit(ctx, *kitPath, &agent, &imageRef, profile, &kitPaths, &kitEnv, &oauthCredentials); err != nil {
			return createOptions{}, false, err
		}
		workspaceFlags = kitPaths
		envFlags = stringListFlag(kitEnv)
	}
	applyAgentDefaults(agent, &imageRef, privileged)
	cpuCount, memoryMiB, err := validateCreateResources(*cpus, *memory)
	if err != nil {
		return createOptions{}, false, err
	}
	for _, target := range denyWriteFlags {
		workspaceFlags = append(workspaceFlags, target+":ro")
	}
	workspaces, err := resolveCreateWorkspaces(workspaceFlags, paths)
	if err != nil {
		return createOptions{}, false, err
	}
	env, err := buildExecEnv(envFlags, envFileFlags)
	if err != nil {
		return createOptions{}, false, err
	}
	ports, allow, deny, err := resolveCreateNetwork(publishFlags, allowFlags, denyFlags)
	if err != nil {
		return createOptions{}, false, err
	}
	workspace := ""
	if len(workspaces) > 0 {
		workspace = workspaces[0].Path
	}
	return createOptions{
		name: name, agent: agent, image: imageRef, workspace: workspace, idempotencyKey: *idempotency,
		workspaces: workspaces, ports: ports, allow: allow, deny: deny,
		cpus: cpuCount, memoryMiB: memoryMiB, env: env, oauthCredentials: oauthCredentials, profile: *profile, privileged: *privileged,
	}, false, nil
}

func (r *Runner) get(ctx context.Context, args []string) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx get <id>")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	id, err := findExecSandbox(ctx, client, args[0])
	if err != nil {
		r.error(err)
		return 1
	}
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		r.error(err)
		return 1
	}
	r.printSandbox(sb)
	return 0
}

func (r *Runner) start(ctx context.Context, args []string) int {
	return r.lifecycle(ctx, "start", args)
}

func (r *Runner) stop(ctx context.Context, args []string) int {
	return r.lifecycle(ctx, "stop", args)
}

type removeOptions struct {
	force   bool
	all     bool
	format  string
	targets []string
}

func (r *Runner) remove(ctx context.Context, args []string) int {
	opts, help, err := parseRemoveOptions(args)
	if help {
		_, _ = fmt.Fprint(r.Out, removeUsage)
		return 0
	}
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx rm: %v\n", err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	targets, code := r.prepareRemoval(ctx, client, opts)
	if code >= 0 {
		return code
	}
	operations, removed, failed := r.deleteSandboxes(ctx, client, targets)
	if code := r.renderRemoval(opts.format, operations, removed); code >= 0 {
		return code
	}
	if failed {
		return 1
	}
	return 0
}

func (r *Runner) prepareRemoval(ctx context.Context, client sdk.Client, opts removeOptions) ([]string, int) {
	targets := opts.targets
	if opts.all {
		var err error
		targets, err = allSandboxIDs(ctx, client)
		if err != nil {
			r.error(err)
			return nil, 1
		}
	}
	if len(targets) == 0 {
		if err := renderOperations(r.Out, opts.format, nil); err != nil {
			r.error(err)
			return nil, 1
		}
		return nil, 0
	}
	if opts.force {
		return targets, -1
	}
	confirmed, err := r.confirmRemoval(len(targets))
	if err != nil {
		r.error(err)
		return nil, 1
	}
	if !confirmed {
		_, _ = fmt.Fprintln(r.Out, "Removal canceled")
		return nil, 0
	}
	return targets, -1
}

func (r *Runner) renderRemoval(format string, operations []*sdk.Operation, removed []string) int {
	if format != listFormatTable {
		if err := renderOperations(r.Out, format, operations); err != nil {
			r.error(err)
			return 1
		}
		return -1
	}
	for _, name := range removed {
		_, _ = fmt.Fprintf(r.Out, "Removed sandbox %s\n", name)
	}
	return -1
}

func parseRemoveOptions(args []string) (removeOptions, bool, error) {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	force := fs.Bool("force", false, "delete without confirmation and allow running sandboxes")
	fs.BoolVar(force, "f", false, "delete without confirmation and allow running sandboxes")
	all := fs.Bool("all", false, "remove all sandboxes")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return removeOptions{}, true, nil
		}
		return removeOptions{}, false, err
	}
	if (*all && fs.NArg() != 0) || (!*all && fs.NArg() < 1) {
		return removeOptions{}, false, errors.New("usage: rsbx rm [-f|--force] [--format table|json|yaml] SANDBOX... | --all")
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		return removeOptions{}, false, err
	}
	return removeOptions{force: *force, all: *all, format: selected, targets: fs.Args()}, false, nil
}

func allSandboxIDs(ctx context.Context, client sdk.Client) ([]string, error) {
	items, err := collectSandboxes(ctx, client, 200)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(items))
	for i := range items {
		ids = append(ids, items[i].ID)
	}
	return ids, nil
}

func (r *Runner) deleteSandboxes(ctx context.Context, client sdk.Client, targets []string) ([]*sdk.Operation, []string, bool) {
	failed := false
	operations := make([]*sdk.Operation, 0, len(targets))
	removed := make([]string, 0, len(targets))
	for _, name := range targets {
		id, err := findExecSandbox(ctx, client, name)
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		op, err := client.Sandboxes().Delete(ctx, id, sdk.DeleteOptions{Force: true})
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		if op != nil && op.State == sdk.StateFailed {
			r.error(fmt.Errorf("remove sandbox %s failed: %s", name, op.Error))
			failed = true
			continue
		}
		operations = append(operations, op)
		removed = append(removed, name)
	}
	return operations, removed, failed
}

func (r *Runner) confirmRemoval(count int) (bool, error) {
	file, ok := r.In.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return false, errors.New("removal confirmation requires a terminal; use --force to skip confirmation")
	}
	if _, err := fmt.Fprintf(r.Err, "Remove %d sandbox(es)? [y/N] ", count); err != nil {
		return false, fmt.Errorf("write removal prompt: %w", err)
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read removal confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == answerShortYes || answer == answerYes, nil
}

func (r *Runner) wait(ctx context.Context, args []string) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx wait <operation-id>")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	op, err := client.Operations().Wait(ctx, args[0])
	if err != nil {
		r.error(err)
		return 1
	}
	r.printOperation(op)
	if op != nil && op.State == sdk.StateFailed {
		return 1
	}
	return 0
}

func (r *Runner) lifecycle(ctx context.Context, name string, args []string) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(r.Err)
	grace := fs.Duration("grace", 0, "grace period")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure(name, err)
	}
	if fs.NArg() < 1 {
		_, _ = fmt.Fprintf(r.Err, "usage: rsbx %s [--format table|json|yaml] [--json] [flags] SANDBOX...\n", name)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	failed := false
	var operations []*sdk.Operation
	for _, target := range fs.Args() {
		op, err := r.runLifecycleTarget(ctx, client, name, target, *grace)
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		operations = append(operations, op)
		if selected == listFormatTable {
			_, _ = fmt.Fprintf(r.Out, "%s sandbox %s\n", lifecyclePastTense(name), target)
		}
	}
	if selected != listFormatTable {
		if err := renderOperations(r.Out, selected, operations); err != nil {
			r.error(err)
			return 1
		}
	}
	if failed {
		return 1
	}
	return 0
}

// runLifecycleTarget starts or stops one sandbox and returns its operation.
func (r *Runner) runLifecycleTarget(ctx context.Context, client sdk.Client, name, target string, grace time.Duration) (*sdk.Operation, error) {
	id, err := findExecSandbox(ctx, client, target)
	if err != nil {
		return nil, err
	}
	var op *sdk.Operation
	if name == startCommand {
		op, err = client.Sandboxes().Start(ctx, id)
	} else {
		op, err = client.Sandboxes().Stop(ctx, id, sdk.StopOptions{Grace: grace})
	}
	if err != nil {
		return nil, err
	}
	if op != nil && op.State == sdk.StateFailed {
		return nil, fmt.Errorf("%s sandbox %s failed: %s", name, target, op.Error)
	}
	return op, nil
}

func lifecyclePastTense(name string) string {
	switch name {
	case stopCommand:
		return "Stopped"
	case startCommand:
		return "Started"
	default:
		return name + "ed"
	}
}

func (r *Runner) client() (sdk.Client, error) {
	if r.NewClient == nil {
		return sdk.New(sdk.Config{Address: r.Socket})
	}
	return r.NewClient(r.Socket)
}

func (r *Runner) printOperation(op *sdk.Operation) {
	if op == nil {
		_, _ = fmt.Fprintln(r.Out, "ok")
		return
	}
	_, _ = fmt.Fprintf(r.Out, "%s\t%s\t%s\t%s\n", op.ID, op.Kind, op.State, op.Error)
}

func (r *Runner) printSandbox(sb *sdk.Sandbox) {
	if sb == nil {
		_, _ = fmt.Fprintln(r.Out, "not found")
		return
	}
	_, _ = fmt.Fprintf(r.Out, "id: %s\nname: %s\nstate: %s\nagent: %s\npolicy_profile: %s\ndetached: %t\nlast_used_at: %s\nimage: %s\nworkspace: %s\nworkspaces: %s\nports: %s\nallow: %s\ndeny: %s\ncpus: %d\nmemory_mib: %d\nstopped_at: %s\ngeneration: %d\ncreated: %s\n",
		sb.ID, sb.Name, sb.State, formatAgent(sb.Agent), sb.PolicyProfile, sb.Detached, formatTime(sb.LastUsedAt), sb.Image, sb.Workspace, formatWorkspaces(sb), formatPorts(sb), formatRules(sb.Allow), formatRules(sb.Deny),
		sb.CPUs, sb.MemoryMiB, formatTime(sb.StoppedAt), sb.Generation, formatTime(sb.CreatedAt))
}

func (r *Runner) usage() {
	const help = `Rheic Sandboxes manages isolated local environments for coding agents.

Usage:
  rsbx COMMAND

Sandbox commands:
  run, attach, create, exec, cp, ls, get, start, stop, rm, prune, wait, ports

Management commands:
  agents, daemon, diagnose, env, login, logout, policy, reset, secret, settings, tui

Extensions:
  kit       Inspect local kit files; registry kits and builders are unavailable
  template  List and inspect built-in templates

Unsupported Docker Sandboxes commands:
  mcp, move, setup, skills, ttl, volume

Flags:
      --socket PATH  Local daemon endpoint
  -h, --help         Show command help

Use "rsbx COMMAND --help" for command details.
`
	if _, err := io.WriteString(r.Out, help); err != nil {
		r.error(err)
	}
}

func (r *Runner) error(err error) {
	_, _ = fmt.Fprintln(r.Err, err)
}

func defaultSocket() string {
	if socket := strings.TrimSpace(os.Getenv("SANDBOXES_SOCKET")); socket != "" {
		return socket
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".sandboxes/sandboxesd.sock"
	}
	return filepath.Join(home, ".sandboxes", "sandboxesd.sock")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func formatWorkspaces(sb *sdk.Sandbox) string {
	workspaces := sb.Workspaces
	if len(workspaces) == 0 && sb.Workspace != "" {
		workspaces = []sdk.Workspace{{Path: sb.Workspace}}
	}
	if len(workspaces) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(workspaces))
	for i := range workspaces {
		mode := "rw"
		if workspaces[i].ReadOnly {
			mode = "ro"
		}
		parts = append(parts, workspaces[i].Path+" ("+mode+")")
	}
	return strings.Join(parts, ", ")
}

func formatPorts(sb *sdk.Sandbox) string {
	if len(sb.Ports) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(sb.Ports))
	for i := range sb.Ports {
		protocol := sb.Ports[i].Protocol
		if protocol == "" {
			protocol = tcpProtocol
		}
		parts = append(parts, fmt.Sprintf("%d->%d/%s", sb.Ports[i].Host, sb.Ports[i].Guest, protocol))
	}
	return strings.Join(parts, ", ")
}

func resolveCreateNetwork(publish, allow, deny []string) ([]sdk.Port, []sdk.NetworkRule, []sdk.NetworkRule, error) {
	ports, err := resolvePorts(publish)
	if err != nil {
		return nil, nil, nil, err
	}
	allowRules, err := resolveNetworkRules(allow)
	if err != nil {
		return nil, nil, nil, err
	}
	denyRules, err := resolveNetworkRules(deny)
	if err != nil {
		return nil, nil, nil, err
	}
	return ports, allowRules, denyRules, nil
}

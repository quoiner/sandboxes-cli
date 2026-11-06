package command

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	sdk "github.com/rheic/sandboxes-go-sdk"
	"golang.org/x/term"

	"github.com/rheic/sandboxes-cli/internal/envfile"
)

func (r *Runner) environmentCreate(ctx context.Context, args []string) int {
	options, err := parseEnvironmentCreateOptions(r, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("env create", err)
	}
	plan, environment, workspacePath, memory, err := loadEnvironmentCreatePlan(options)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env create: %s\n", err)
		return 1
	}
	defer clear(environment)
	if err := r.approveEnvironmentCreate(plan, options.force); err != nil {
		if errors.Is(err, errEnvironmentCanceled) {
			_, _ = fmt.Fprintln(r.Out, "Environment create canceled")
			return 0
		}
		r.error(err)
		return 1
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	request := buildEnvironmentCreateRequest(plan, environment, workspacePath, memory)
	op, err := client.Sandboxes().Create(ctx, request)
	clear(environment)
	if err != nil {
		r.error(err)
		return 1
	}
	r.printCreatedSandbox(ctx, client, request.Name, op)
	return 0
}

type environmentCreateOptions struct {
	force     bool
	name      string
	paths     []string
	arguments envfile.ArgumentOverrides
}

func parseEnvironmentCreateOptions(r *Runner, args []string) (environmentCreateOptions, error) {
	fs := flag.NewFlagSet("env create", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	force := fs.Bool("force", false, "apply without prompting")
	fs.BoolVar(force, "f", false, "apply without prompting")
	name := fs.String("name", "", "override the environment sandbox name")
	var envArguments, envArgumentFiles repeatedStringFlag
	fs.Var(&envArguments, "env-arg", "value for a declared environment argument (repeatable)")
	fs.Var(&envArgumentFiles, "env-args-file", "file of name=value environment arguments (repeatable)")
	fs.Usage = func() {
		_, _ = fmt.Fprint(fs.Output(), "Usage: rsbx env create [PATH...] [--force] [--name NAME]\n\nApply the supported environment plan and create a sandbox without attaching.\nUnsupported fields fail closed.\n")
	}
	valueFlags := map[string]bool{"--name": true, "--env-arg": true, "--env-args-file": true}
	if err := fs.Parse(reorderFlagArgs(args, valueFlags)); err != nil {
		return environmentCreateOptions{}, err
	}
	return environmentCreateOptions{force: *force, name: *name, paths: fs.Args(), arguments: envfile.ArgumentOverrides{Files: envArgumentFiles, Values: envArguments}}, nil
}

func loadEnvironmentCreatePlan(options environmentCreateOptions) (envfile.Plan, map[string]string, string, uint32, error) {
	plan, environment, err := loadEnvironmentForExecution(options.paths, options.arguments)
	if err != nil {
		return envfile.Plan{}, nil, "", 0, err
	}
	validated, err := validateEnvironmentValues(environment)
	clear(environment)
	if err != nil {
		return envfile.Plan{}, nil, "", 0, err
	}
	prepared, workspacePath, memory, err := prepareEnvironmentCreatePlan(plan, options.paths, options.name)
	if err != nil {
		clear(validated)
		return envfile.Plan{}, nil, "", 0, err
	}
	return prepared, validated, workspacePath, memory, nil
}

func validateEnvironmentValues(values map[string]string) (map[string]string, error) {
	entries := make([]string, 0, len(values))
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entries = append(entries, key+"="+values[key])
	}
	validated, err := buildExecEnv(entries, nil)
	clear(entries)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(validated))
	for _, entry := range validated {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			clear(result)
			return nil, errors.New("invalid environment entry")
		}
		result[key] = value
	}
	clear(validated)
	return result, nil
}

func prepareEnvironmentCreatePlan(plan envfile.Plan, paths []string, name string) (envfile.Plan, string, uint32, error) {
	if err := applyEnvironmentName(&plan, name); err != nil {
		return envfile.Plan{}, "", 0, err
	}
	if err := validateRunAgent(plan.Agent); err != nil {
		return envfile.Plan{}, "", 0, err
	}
	var memory uint32
	if plan.Memory != "" {
		value, err := parseMemoryMiB(plan.Memory)
		if err != nil {
			return envfile.Plan{}, "", 0, err
		}
		memory = value
	}
	workspacePath := plan.Workspace
	if workspacePath == "" {
		value, err := environmentProjectDir(paths)
		if err != nil {
			return envfile.Plan{}, "", 0, err
		}
		workspacePath = value
		plan.Workspace = workspacePath
	}
	if plan.Name == "" {
		base := workspaceNameBase([]string{workspacePath})
		if base == "" {
			return envfile.Plan{}, "", 0, errors.New("derive sandbox name from environment workspace")
		}
		plan.Name = plan.Agent + "-" + base
		if !validRunName(plan.Name) {
			return envfile.Plan{}, "", 0, errors.New("derived environment sandbox name is invalid")
		}
	}
	return plan, workspacePath, memory, nil
}

func buildEnvironmentCreateRequest(plan envfile.Plan, environment map[string]string, workspacePath string, memory uint32) sdk.CreateRequest {
	workspaces := make([]sdk.Workspace, 0, 1+len(plan.AdditionalWorkspaces))
	workspaces = append(workspaces, sdk.Workspace{Path: workspacePath})
	for _, workspace := range plan.AdditionalWorkspaces {
		workspaces = append(workspaces, sdk.Workspace{Path: workspace.Path, ReadOnly: workspace.ReadOnly})
	}
	ports := make([]sdk.Port, 0, len(plan.Ports))
	for _, port := range plan.Ports {
		protocol := port.Protocol
		if protocol == "" {
			protocol = tcpProtocol
		}
		host := uint16(0)
		if port.Host != nil {
			host = *port.Host
		}
		ports = append(ports, sdk.Port{Host: host, Guest: port.Sandbox, Protocol: protocol, HostIP: port.HostIP})
	}
	var cpus uint32
	if plan.CPUs != nil {
		cpus = *plan.CPUs
	}
	image := ""
	privileged := false
	applyAgentDefaults(plan.Agent, &image, &privileged)
	return sdk.CreateRequest{
		Name: plan.Name, Image: image, Workspace: workspacePath, Workspaces: workspaces,
		Ports: ports, Agent: plan.Agent, CPUs: cpus, MemoryMiB: memory,
		Env: environment, Privileged: privileged,
	}
}

func (r *Runner) environmentExec(ctx context.Context, args []string) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, _ = fmt.Fprintln(r.Out, "Usage: rsbx env exec [PATH...] -- COMMAND [ARG...] [--name NAME] [--env-arg NAME=VALUE]")
		_, _ = fmt.Fprintln(r.Out, "Runs a command in a matching existing environment sandbox, starting it if stopped. Create a missing sandbox first.")
		return 0
	}
	separator := slices.Index(args, "--")
	if separator < 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx env exec [PATH...] -- COMMAND [ARG...]")
		return 2
	}
	options, err := parseEnvironmentCreateOptions(r, args[:separator])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("env exec", err)
	}
	command := args[separator+1:]
	if len(command) == 0 {
		_, _ = fmt.Fprintln(r.Err, "rsbx env exec: command is required after --")
		return 2
	}
	plan, environment, workspacePath, _, err := loadEnvironmentCreatePlan(options)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env exec: %s\n", err)
		return 1
	}
	clear(environment)
	request := buildEnvironmentCreateRequest(plan, nil, workspacePath, 0)
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 125
	}
	defer func() { _ = client.Close() }()
	sandbox, found, err := lookupSandboxByName(ctx, client, plan.Name)
	if err != nil {
		r.error(err)
		return 125
	}
	if !found {
		_, _ = fmt.Fprintf(r.Err, "rsbx env exec: environment sandbox %q does not exist; run 'rsbx env create' first\n", plan.Name)
		return 125
	}
	if sandbox.Agent != plan.Agent {
		_, _ = fmt.Fprintln(r.Err, "rsbx env exec: existing sandbox agent does not match the environment")
		return 125
	}
	if err := checkReusedWorkspace(sandbox, request.Workspaces); err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env exec: %s\n", err)
		return 125
	}
	if err := ensureSandboxRunning(ctx, client, sandbox); err != nil {
		r.error(err)
		return 125
	}
	return r.exec(ctx, append([]string{sandbox.ID}, command...))
}

func (r *Runner) environmentRun(ctx context.Context, args []string) int {
	options, agentArgs, detach, err := parseEnvironmentRunOptions(r, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("env run", err)
	}
	plan, environment, workspacePath, memory, err := loadEnvironmentCreatePlan(options)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env run: %s\n", err)
		return 1
	}
	defer clear(environment)
	if err := r.approveEnvironmentCreate(plan, options.force); err != nil {
		if errors.Is(err, errEnvironmentCanceled) {
			_, _ = fmt.Fprintln(r.Out, "Environment run canceled")
			return 0
		}
		r.error(err)
		return 1
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	entries := environmentEntries(environment)
	clear(environment)
	entries, err = prepareAgentCredentials(ctx, client, plan.Agent, plan.Name, entries)
	if err != nil {
		r.error(err)
		return 1
	}
	defer clear(entries)
	if err := validateOAuthProxyEnvironment(entries); err != nil {
		r.error(err)
		return 1
	}
	request := buildEnvironmentCreateRequest(plan, envMap(entries), workspacePath, memory)
	sandbox, created, err := r.resolveEnvironmentRunSandbox(ctx, client, plan, request, entries)
	if err != nil {
		r.error(err)
		return 1
	}
	if sandbox.ID == "" {
		return 0
	}
	opts := runOptions{name: plan.Name, detach: detach}
	if plan.CPUs != nil {
		opts.cpus = uint(*plan.CPUs)
	}
	if plan.Memory != "" {
		opts.memory = plan.Memory
	}
	resources := runResources{cpus: request.CPUs, memory: request.MemoryMiB, env: entries, ports: request.Ports}
	return r.runAttached(ctx, client, opts, sandbox, created, plan.Agent, request.Workspaces, true, agentArgs, resources)
}

func (r *Runner) resolveEnvironmentRunSandbox(ctx context.Context, client sdk.Client, plan envfile.Plan, request sdk.CreateRequest, environment []string) (*sdk.Sandbox, bool, error) {
	sandbox, found, err := lookupSandboxByName(ctx, client, plan.Name)
	if err != nil {
		return nil, false, err
	}
	if found {
		return r.adoptEnvironmentSandbox(sandbox, plan, request)
	}
	request.Env = envMap(environment)
	op, err := client.Sandboxes().Create(ctx, request)
	if err != nil {
		return nil, false, err
	}
	if op != nil && op.SandboxID != "" {
		createdSandbox, getErr := client.Sandboxes().Get(ctx, op.SandboxID)
		if getErr != nil {
			return nil, false, getErr
		}
		return createdSandbox, true, nil
	}
	var created bool
	sandbox, created, err = lookupSandboxByName(ctx, client, plan.Name)
	if err == nil && !created {
		err = errors.New("sandbox creation returned no sandbox")
	}
	return sandbox, err == nil, err
}

func (r *Runner) adoptEnvironmentSandbox(sandbox *sdk.Sandbox, plan envfile.Plan, request sdk.CreateRequest) (*sdk.Sandbox, bool, error) {
	if sandbox.Agent != plan.Agent {
		return nil, false, errors.New("existing sandbox agent does not match the environment")
	}
	if err := checkReusedWorkspace(sandbox, request.Workspaces); err != nil {
		return nil, false, err
	}
	confirmed, err := r.confirmEnvironmentAdoption(sandbox.Name)
	if err != nil {
		return nil, false, err
	}
	if !confirmed {
		_, _ = fmt.Fprintln(r.Out, "Environment adoption canceled")
		return nil, false, nil
	}
	return sandbox, false, nil
}

func parseEnvironmentRunOptions(r *Runner, args []string) (environmentCreateOptions, []string, bool, error) {
	if slices.Contains(args, helpFlag) || slices.Contains(args, helpShort) {
		_, _ = fmt.Fprint(r.Out, "Usage: rsbx env run [PATH...] [--detach] [--force] [--name NAME] [-- AGENT-ARGS...]\n\nCreate an environment if absent, then start and attach to its configured agent. Reusing an existing sandbox requires interactive adoption approval.\n")
		return environmentCreateOptions{}, nil, false, flag.ErrHelp
	}
	head, agentArgs := splitAgentArgs(args)
	filtered := make([]string, 0, len(head))
	detach := false
	for _, arg := range head {
		if arg == "--detach" || arg == "-d" {
			detach = true
			continue
		}
		filtered = append(filtered, arg)
	}
	options, err := parseEnvironmentCreateOptions(r, filtered)
	return options, agentArgs, detach, err
}

func environmentEntries(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entries := make([]string, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, key+"="+values[key])
	}
	return entries
}

func (r *Runner) confirmEnvironmentAdoption(name string) (bool, error) {
	file, ok := r.In.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return false, errors.New("environment adoption requires a terminal; --force does not approve adoption")
	}
	if _, err := fmt.Fprintf(r.Err, "Sandbox %s already exists. Adopt and attach to it? [y/N] ", name); err != nil {
		return false, errors.New("write environment adoption prompt failed")
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, errors.New("read environment adoption confirmation")
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == answerShortYes || answer == answerYes, nil
}

var errEnvironmentCanceled = errors.New("environment creation was canceled")

func (r *Runner) approveEnvironmentCreate(plan envfile.Plan, force bool) error {
	var out strings.Builder
	fmt.Fprintln(&out, "Environment create plan")
	fmt.Fprintf(&out, "Name: %s\nAgent: %s\nWorkspace: %s\n", displayPreviewValue(plan.Name, plan.NameRedacted), displayPreviewValue(plan.Agent, plan.AgentRedacted), displayPreviewPath(plan.Workspace, plan.WorkspaceRedacted))
	fmt.Fprintf(&out, "Additional workspaces: %d\n", len(plan.AdditionalWorkspaces))
	for _, workspace := range plan.AdditionalWorkspaces {
		mode := "read-write"
		if workspace.ReadOnly {
			mode = "read-only"
		}
		fmt.Fprintf(&out, "  %s (%s)\n", displayPreviewPath(workspace.Path, workspace.Redacted), mode)
	}
	writePortPreview(&out, plan.Ports)
	writeRedactedNames(&out, "Environment keys", plan.EnvironmentKeys)
	if plan.CPUs != nil {
		if plan.CPUsRedacted {
			fmt.Fprintln(&out, "CPUs: <redacted>")
		} else {
			fmt.Fprintf(&out, "CPUs: %d\n", *plan.CPUs)
		}
	}
	if plan.Memory != "" {
		fmt.Fprintf(&out, "Memory: %s\n", displayPreviewValue(plan.Memory, plan.MemoryRedacted))
	}
	if _, err := fmt.Fprint(r.Out, out.String()); err != nil {
		return errors.New("write environment create plan failed")
	}
	if force {
		return nil
	}
	file, ok := r.In.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return errors.New("environment approval requires a terminal; use --force to approve this invocation")
	}
	if _, err := fmt.Fprint(r.Err, "Apply this environment plan and create the sandbox? [y/N] "); err != nil {
		return errors.New("write environment approval prompt failed")
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("read environment approval")
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != answerShortYes && answer != answerYes {
		return errEnvironmentCanceled
	}
	return nil
}

func loadEnvironmentForExecution(paths []string, overrides envfile.ArgumentOverrides) (envfile.Plan, map[string]string, error) {
	if len(paths) != 0 {
		return envfile.LoadForExecution(paths, overrides)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return envfile.Plan{}, nil, errors.New("resolve default environment paths")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return envfile.Plan{}, nil, errors.New("resolve default environment paths")
	}
	return envfile.LoadDefaultForExecution(homeDir, workingDir, overrides)
}

func environmentProjectDir(paths []string) (string, error) {
	if len(paths) == 0 {
		return os.Getwd()
	}
	first := paths[0]
	info, err := os.Stat(first)
	if err != nil {
		return "", errors.New("resolve environment project directory")
	}
	if !info.IsDir() {
		first = filepath.Dir(first)
	}
	abs, err := filepath.Abs(first)
	if err != nil {
		return "", errors.New("resolve environment project directory")
	}
	return filepath.Clean(abs), nil
}

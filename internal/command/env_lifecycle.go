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
	if err := r.approveEnvironmentCreate(plan, options.force, commandCreate); err != nil {
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
	valueFlags := map[string]bool{nameFlag: true, envArgFlag: true, envArgsFileFlag: true}
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
	if environmentExecHelpRequested(args) {
		_, _ = fmt.Fprintln(r.Out, "Usage: rsbx env exec [flags] [PATH...] [-- COMMAND [ARG...]]")
		_, _ = fmt.Fprintln(r.Out, "Runs a command in a matching existing environment sandbox, starting it if stopped. Without --, positional arguments are the command and the environment path defaults to the current directory.")
		return 0
	}
	createArgs, execArgs, command, err := splitEnvironmentExecArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env exec: %s\n", err)
		return 2
	}
	if len(command) == 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx env exec [flags] [PATH...] [--] COMMAND [ARG...]")
		return 2
	}
	options, err := parseEnvironmentCreateOptions(r, createArgs)
	if err != nil {
		return r.flagParseFailure("env exec", err)
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
	execArgs = append(execArgs, sandbox.ID)
	execArgs = append(execArgs, command...)
	return r.exec(ctx, execArgs)
}

func environmentExecHelpRequested(args []string) bool {
	separator := slices.Index(args, "--")
	if separator >= 0 {
		return slices.Contains(args[:separator], helpFlag) || slices.Contains(args[:separator], helpShort)
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == helpFlag || arg == helpShort {
			return true
		}
		_, _, consumed, recognized, _ := consumeEnvironmentExecFlag(args, i)
		if recognized {
			i += consumed
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			return false
		}
	}
	return false
}

func splitEnvironmentExecArgs(args []string) ([]string, []string, []string, error) {
	separator := slices.Index(args, "--")
	explicitPaths := separator >= 0
	head := args
	var command []string
	if explicitPaths {
		head = args[:separator]
		command = append([]string(nil), args[separator+1:]...)
	}
	createArgs := make([]string, 0, len(head))
	execArgs := make([]string, 0, len(head))
	for i := 0; i < len(head); i++ {
		arg := head[i]
		configFlagArgs, executionFlagArgs, consumed, recognized, err := consumeEnvironmentExecFlag(head, i)
		if err != nil {
			return nil, nil, nil, err
		}
		if recognized {
			createArgs = append(createArgs, configFlagArgs...)
			execArgs = append(execArgs, executionFlagArgs...)
			i += consumed
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return nil, nil, nil, fmt.Errorf("unsupported flag %s", arg)
		}
		if !explicitPaths {
			command = append(command, head[i:]...)
			break
		}
		createArgs = append(createArgs, arg)
	}
	return createArgs, execArgs, command, nil
}

func consumeEnvironmentExecFlag(args []string, index int) ([]string, []string, int, bool, error) {
	arg := args[index]
	name, _, inline := strings.Cut(arg, "=")
	if name == nameFlag || name == envArgFlag || name == envArgsFileFlag {
		if inline {
			return []string{arg}, nil, 0, true, nil
		}
		if index+1 == len(args) {
			return nil, nil, 0, false, fmt.Errorf("flag %s requires a value", name)
		}
		return []string{arg, args[index+1]}, nil, 1, true, nil
	}
	if execFlagTakesValue(name) {
		if inline {
			return nil, []string{arg}, 0, true, nil
		}
		if index+1 == len(args) {
			return nil, nil, 0, false, fmt.Errorf("flag %s requires a value", name)
		}
		return nil, []string{arg, args[index+1]}, 1, true, nil
	}
	if isEnvironmentExecBooleanFlag(arg) {
		return nil, []string{arg}, 0, true, nil
	}
	return nil, nil, 0, false, nil
}

func isEnvironmentExecBooleanFlag(arg string) bool {
	switch arg {
	case "-i", "--interactive", "-t", "--tty", "-it", "-ti":
		return true
	default:
		return false
	}
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
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	sandbox, found, canceled, err := r.preflightEnvironmentRun(ctx, client, plan, workspacePath, memory, options.force)
	if err != nil {
		r.error(err)
		return 1
	}
	if canceled {
		_, _ = fmt.Fprintln(r.Out, "Environment run canceled")
		return 0
	}
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
	request := buildEnvironmentCreateRequest(plan, nil, workspacePath, memory)
	created := false
	if !found {
		sandbox, err = createEnvironmentRunSandbox(ctx, client, plan.Name, request, entries)
		if err != nil {
			r.error(err)
			return 1
		}
		created = true
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

func (r *Runner) preflightEnvironmentRun(ctx context.Context, client sdk.Client, plan envfile.Plan, workspacePath string, memory uint32, force bool) (*sdk.Sandbox, bool, bool, error) {
	sandbox, found, err := lookupSandboxByName(ctx, client, plan.Name)
	if err != nil {
		return nil, false, false, err
	}
	if found {
		validated, err := validateEnvironmentRunSandbox(sandbox, plan, buildEnvironmentCreateRequest(plan, nil, workspacePath, memory))
		return validated, true, false, err
	}
	err = r.approveEnvironmentCreate(plan, force, commandRun)
	if errors.Is(err, errEnvironmentCanceled) {
		return nil, false, true, nil
	}
	return nil, false, false, err
}

func createEnvironmentRunSandbox(ctx context.Context, client sdk.Client, name string, request sdk.CreateRequest, environment []string) (*sdk.Sandbox, error) {
	request.Env = envMap(environment)
	defer clear(request.Env)
	op, err := client.Sandboxes().Create(ctx, request)
	if err != nil {
		return nil, err
	}
	if op != nil && op.SandboxID != "" {
		return client.Sandboxes().Get(ctx, op.SandboxID)
	}
	sandbox, found, err := lookupSandboxByName(ctx, client, name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("sandbox creation returned no sandbox")
	}
	return sandbox, nil
}

func (r *Runner) environmentRemove(ctx context.Context, args []string) int {
	if slices.Contains(args, helpFlag) || slices.Contains(args, helpShort) {
		_, _ = fmt.Fprint(r.Out, "Usage: rsbx env rm [PATH...] [--force] [--name NAME]\n\nRemove the sandbox matching this environment's name, agent, and workspace. Global credential bindings are not removed.\n")
		return 0
	}
	options, err := parseEnvironmentCreateOptions(r, args)
	if err != nil {
		return r.flagParseFailure("env rm", err)
	}
	plan, err := loadEnvironmentPlan(options.paths, options.arguments)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env rm: %s\n", err)
		return 1
	}
	plan, workspacePath, _, err := prepareEnvironmentCreatePlan(plan, options.paths, options.name)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env rm: %s\n", err)
		return 1
	}
	request := buildEnvironmentCreateRequest(plan, nil, workspacePath, 0)
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	sandbox, found, err := findEnvironmentRemovalTarget(ctx, client, plan, request)
	if err != nil {
		r.error(err)
		return 1
	}
	if !found {
		_, _ = fmt.Fprintf(r.Out, "Environment sandbox %q does not exist\n", sanitizeTerminalText(plan.Name))
		return 0
	}
	if !options.force {
		confirmed, err := r.confirmRemoval(1)
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "Environment removal canceled")
			return 0
		}
	}
	op, err := client.Sandboxes().Delete(ctx, sandbox.ID, sdk.DeleteOptions{Force: options.force})
	if err != nil {
		r.error(err)
		return 1
	}
	if op != nil && op.State == sdk.StateFailed {
		r.error(fmt.Errorf("remove environment sandbox %s failed: %s", plan.Name, op.Error))
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Removed environment sandbox %s\n", sanitizeTerminalText(plan.Name))
	return 0
}

func findEnvironmentRemovalTarget(ctx context.Context, client sdk.Client, plan envfile.Plan, request sdk.CreateRequest) (*sdk.Sandbox, bool, error) {
	sandbox, found, err := lookupSandboxByName(ctx, client, plan.Name)
	if err != nil || !found {
		return sandbox, found, err
	}
	if sandbox.Agent != plan.Agent {
		return nil, false, errors.New("existing sandbox agent does not match the environment")
	}
	if err := checkReusedWorkspace(sandbox, request.Workspaces); err != nil {
		return nil, false, err
	}
	return sandbox, true, nil
}

func validateEnvironmentRunSandbox(sandbox *sdk.Sandbox, plan envfile.Plan, request sdk.CreateRequest) (*sdk.Sandbox, error) {
	if sandbox.Agent != plan.Agent {
		return nil, errors.New("existing sandbox agent does not match the environment")
	}
	if err := checkReusedWorkspace(sandbox, request.Workspaces); err != nil {
		return nil, err
	}
	return sandbox, nil
}

func parseEnvironmentRunOptions(r *Runner, args []string) (environmentCreateOptions, []string, bool, error) {
	head := args
	if separator := slices.Index(args, "--"); separator >= 0 {
		head = args[:separator]
	}
	if slices.Contains(head, helpFlag) || slices.Contains(head, helpShort) {
		_, _ = fmt.Fprint(r.Out, "Usage: rsbx env run [PATH...] [--detach] [--force] [--name NAME] [-- AGENT-ARGS...]\n\nCreate an environment if absent, then start and attach to its configured agent. Existing matching sandboxes are reused without re-provisioning.\n")
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

var errEnvironmentCanceled = errors.New("environment creation was canceled")

func (r *Runner) approveEnvironmentCreate(plan envfile.Plan, force bool, action string) error {
	var out strings.Builder
	fmt.Fprintf(&out, "Environment %s plan\n", action)
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
	if _, err := fmt.Fprintf(r.Err, "Apply this environment plan and %s the sandbox? [y/N] ", action); err != nil {
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

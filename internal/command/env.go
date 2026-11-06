package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rheic/sandboxes-cli/internal/envfile"
)

const previewDefault = "default"

type repeatedStringFlag []string

func (f *repeatedStringFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *repeatedStringFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func (r *Runner) environment(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		_, _ = fmt.Fprint(r.Out, "Usage: rsbx env COMMAND [PATH...]\n\nCommands: plan, create, run, exec, rm.\n\nUse 'plan' for a static preview, 'create' to apply without attaching, 'run' to create or attach to an agent, 'exec' to run a command in an existing environment, or 'rm' to remove its matching sandbox. Environment values are never displayed.\n")
		return 0
	}
	switch args[0] {
	case "plan":
		return r.environmentPlan(args[1:])
	case commandCreate:
		return r.environmentCreate(ctx, args[1:])
	case commandExec:
		return r.environmentExec(ctx, args[1:])
	case commandRun:
		return r.environmentRun(ctx, args[1:])
	case "rm":
		return r.environmentRemove(ctx, args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "rsbx env %s: unsupported\n", args[0])
		return 1
	}
}

func (r *Runner) environmentPlan(args []string) int {
	fs := flag.NewFlagSet("env plan", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	name := fs.String("name", "", "override the environment sandbox name")
	var envArguments, envArgumentFiles repeatedStringFlag
	fs.Var(&envArguments, "env-arg", "value for an argument declared in sbxenv.yaml (repeatable)")
	fs.Var(&envArgumentFiles, "env-args-file", "file of name=value environment arguments (repeatable)")
	fs.Usage = func() {
		_, _ = fmt.Fprint(fs.Output(), "Usage: rsbx env plan [PATH...] [flags]\n\nWithout PATH, read sbxenv.yaml from the current directory and merge optional ~/.sbxenv.yaml defaults first. Explicit file or directory paths merge in order and skip user defaults.\nYAML values expand env.projectDir and env.fileDir references. Declared ports are validated and displayed without opening sockets. Argument values are validated, redacted, and interpolated once into YAML values; kit arguments are unsupported.\n  --name NAME                 override the sandbox name\n  --env-arg name=value        set a declared environment argument (repeatable; overrides files)\n  --env-args-file PATH        read name=value arguments (repeatable)\n\nValues passed through --env-arg may be visible in host process listings; use --env-args-file for sensitive values. This is a static preview only; it does not apply changes or inspect daemon state.\n")
	}
	valueFlags := map[string]bool{nameFlag: true, envArgFlag: true, envArgsFileFlag: true}
	if err := fs.Parse(reorderFlagArgs(args, valueFlags)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("env plan", err)
	}
	plan, err := loadEnvironmentPlan(fs.Args(), envfile.ArgumentOverrides{Files: envArgumentFiles, Values: envArguments})
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env plan: %s\n", err)
		return 1
	}
	if err := applyEnvironmentName(&plan, *name); err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env plan: %s\n", err)
		return 1
	}
	var out strings.Builder
	fmt.Fprintln(&out, "Static preview (no changes applied; daemon state not queried)")
	fmt.Fprintf(&out, "Name: %s\nAgent: %s\n", displayPreviewValue(plan.Name, plan.NameRedacted), displayPreviewValue(plan.Agent, plan.AgentRedacted))
	fmt.Fprintf(&out, "Workspace: %s\n", displayPreviewPath(plan.Workspace, plan.WorkspaceRedacted))
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
	writeRedactedNames(&out, "Environment arguments", plan.ArgumentNames)
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
		r.error(errors.New("write environment plan failed"))
		return 1
	}
	return 0
}

func writePortPreview(out *strings.Builder, ports []envfile.Port) {
	fmt.Fprintf(out, "Ports: %d\n", len(ports))
	for _, port := range ports {
		if port.Redacted {
			fmt.Fprintln(out, "  <redacted>")
			continue
		}
		host := "ephemeral"
		if port.Host != nil {
			host = fmt.Sprintf("%d", *port.Host)
		}
		protocol := port.Protocol
		if protocol == "" {
			protocol = previewDefault
		}
		hostIP := port.HostIP
		if hostIP == "" {
			hostIP = previewDefault
		}
		fmt.Fprintf(out, "  sandbox %d -> host %s (%s, hostIP %s)\n", port.Sandbox, host, protocol, hostIP)
	}
}

func writeRedactedNames(out *strings.Builder, label string, names []string) {
	fmt.Fprintf(out, "%s: %d\n", label, len(names))
	for _, name := range names {
		fmt.Fprintf(out, "  %s=<redacted>\n", name)
	}
}

func applyEnvironmentName(plan *envfile.Plan, name string) error {
	if name == "" {
		return nil
	}
	if err := envfile.ValidateName(name); err != nil {
		return err
	}
	plan.Name = name
	plan.NameRedacted = false
	return nil
}

func loadEnvironmentPlan(paths []string, overrides envfile.ArgumentOverrides) (envfile.Plan, error) {
	if len(paths) > 0 {
		return envfile.LoadWithArguments(paths, overrides)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return envfile.Plan{}, errors.New("resolve default environment paths")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return envfile.Plan{}, errors.New("resolve default environment paths")
	}
	return envfile.LoadDefaultWithArguments(homeDir, workingDir, overrides)
}

func displayValue(value string) string {
	if value == "" {
		return "(unset)"
	}
	return value
}

func displayPreviewValue(value string, redacted bool) string {
	if redacted {
		return "<redacted>"
	}
	return displayValue(value)
}

func displayPreviewPath(value string, redacted bool) string {
	if redacted {
		return "<redacted>"
	}
	return displayPath(value)
}

func displayPath(value string) string {
	if value == "" {
		return "(unset)"
	}
	return fmt.Sprintf("%q", value)
}

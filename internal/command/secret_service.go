package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/gdamore/tcell/v3"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

const (
	openAIService     = "openai"
	groqService       = "groq"
	mistralService    = "mistral"
	openrouterService = "openrouter"
	xaiService        = "xai"
	oauthFlag         = "--oauth"
)

var serviceSecretNames = []string{
	anthropicServiceName, copilotAgentName, cursorService, "devin", droidService, githubService, googleService,
	groqService, mistralService, "nebius", openAIService, openrouterService, xaiService,
}

type serviceSecretOutput struct {
	Type        string `json:"type" yaml:"type"`
	Service     string `json:"service" yaml:"service"`
	Username    string `json:"username,omitempty" yaml:"username,omitempty"`
	Scope       string `json:"scope" yaml:"scope"`
	SandboxName string `json:"sandbox_name,omitempty" yaml:"sandbox_name,omitempty"`
	State       string `json:"state" yaml:"state"`
}

func (r *Runner) serviceSecretSet(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{"--sandbox": true, "--token": true, "-t": true, "--ref": true, commandFlag: true, "--refresh": true, forceFlag: false, "-f": false, oauthFlag: false, "--no-verify": false, "--show-error": false})
	fs := flag.NewFlagSet("secret set", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	sandboxName := fs.String("sandbox", "", "scope the secret to one sandbox")
	token := fs.String("token", "", "secret value (less secure: visible in shell history)")
	fs.StringVar(token, "t", "", "secret value (less secure: visible in shell history)")
	ref := fs.String("ref", "", "use a 1Password op:// reference or AWS Secrets Manager ARN")
	command := fs.String("command", "", "run a host shell command to resolve the secret; it can access host files")
	refresh := fs.String("refresh", "", "source refresh policy: on-demand or a duration (default: 55m)")
	noVerify := fs.Bool("no-verify", false, "store the source without resolving it now")
	showError := fs.Bool("show-error", false, "show provider stderr on initial verification failure (may contain secrets)")
	oauth := fs.Bool("oauth", false, "sign in to the OpenAI account on the host")
	force := fs.Bool("force", false, "overwrite an existing secret when --token is used")
	fs.BoolVar(force, "f", false, "overwrite an existing secret when --token is used")
	if code, done := r.parseFlagsOrFail("secret set", fs, args); done {
		return code
	}
	if fs.NArg() > 1 {
		_, _ = fmt.Fprintf(r.Err, "usage: rsbx secret set SERVICE [--sandbox NAME] [--token VALUE] [%s]\n", oauthFlag)
		return 2
	}
	service := ""
	switch {
	case fs.NArg() == 1:
		service = normalizeServiceSecret(fs.Arg(0))
	case *oauth:
		service = openAIService
	default:
		if r.SecretScreen == nil {
			input, ok := r.In.(*os.File)
			if !ok || !term.IsTerminal(int(input.Fd())) {
				r.error(errors.New("choose SERVICE interactively or provide it explicitly"))
				return 2
			}
		}
		selected, err := r.selectServiceSecret()
		if err != nil {
			r.error(err)
			return 1
		}
		if selected == "" {
			_, _ = fmt.Fprintln(r.Out, "Secret selection canceled")
			return 0
		}
		service = selected
	}
	if !validServiceSecret(service) {
		r.error(fmt.Errorf("unknown service %q; use one of: %s", service, strings.Join(serviceSecretNames, ", ")))
		return 2
	}
	if strings.HasPrefix(service, "mcp:") && *sandboxName != "" {
		r.error(errors.New("MCP header secrets use global host-vault scope; --sandbox is not supported"))
		return 2
	}
	return r.finishServiceSecretSet(ctx, service, *sandboxName, *token, *ref, *command, *refresh, *noVerify, *showError, *oauth, *force, flagWasProvided(fs, "ref"), flagWasProvided(fs, "command"))
}

func flagWasProvided(fs *flag.FlagSet, name string) bool {
	provided := false
	fs.Visit(func(value *flag.Flag) {
		if value.Name == name {
			provided = true
		}
	})
	return provided
}

func (r *Runner) finishServiceSecretSet(ctx context.Context, service, sandboxName, token, ref, command, refresh string, noVerify, showError, oauth, force, refProvided, commandProvided bool) int {
	if refProvided && ref == "" || commandProvided && command == "" {
		r.error(errors.New("--ref and --command require a non-empty value"))
		return 2
	}
	if oauth {
		return r.storeOAuthServiceSecret(ctx, service, sandboxName, token, ref, command, refresh, noVerify, showError)
	}
	if ref != "" || command != "" {
		return r.storeServiceSecretSource(ctx, service, sandboxName, token, ref, command, refresh, noVerify, showError, force)
	}
	if refresh != "" || noVerify || showError {
		r.error(errors.New("--refresh, --no-verify, and --show-error require --ref or --command"))
		return 2
	}
	return r.storeServiceSecret(ctx, service, sandboxName, token, force)
}

func (r *Runner) storeOAuthServiceSecret(ctx context.Context, service, sandboxName, token, ref, command, refresh string, noVerify, showError bool) int {
	if ref != "" || command != "" || refresh != "" || noVerify || showError {
		r.error(errors.New("--oauth cannot be combined with dynamic secret source flags"))
		return 2
	}
	return r.serviceSecretOAuthSet(ctx, service, sandboxName, token, ref, command)
}

func (r *Runner) storeServiceSecretSource(ctx context.Context, service, sandboxName, token, reference, command, refresh string, noVerify, showError, force bool) int {
	if reference != "" && command != "" {
		r.error(errors.New("--ref and --command cannot be combined"))
		return 2
	}
	if token != "" {
		r.error(errors.New("--ref and --command cannot be combined with --token"))
		return 2
	}
	if noVerify && showError {
		r.error(errors.New("--show-error cannot be combined with --no-verify"))
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	creator, ok := sdk.SecretSources(client)
	if !ok {
		r.error(errors.New("dynamic secret sources are not supported by this daemon"))
		return 1
	}
	scope := sdk.SecretScopeGlobal
	if sandboxName != "" {
		scope = sdk.SecretScopeSandbox
	}
	opAccount, awsProfile := "", ""
	if strings.HasPrefix(reference, "op://") {
		opAccount = os.Getenv("OP_ACCOUNT")
	}
	if strings.HasPrefix(reference, "arn:") {
		awsProfile = os.Getenv("AWS_PROFILE")
	}
	summary, err := creator.SetSource(ctx, service, scope, sandboxName, sdk.SecretSource{
		Reference: reference, Command: command, Refresh: refresh, NoVerify: noVerify, ShowError: showError,
		OPAccount: opAccount, AWSProfile: awsProfile,
	}, force)
	if err != nil {
		r.error(err)
		return 1
	}
	displayScope := string(summary.Scope)
	if summary.SandboxName != "" {
		displayScope += " " + summary.SandboxName
	}
	_, _ = fmt.Fprintf(r.Out, "Stored %s secret source (%s) in host keychain\n", summary.Service, displayScope)
	return 0
}

func (r *Runner) selectServiceSecret() (string, error) {
	screen := tcell.Screen(nil)
	if r.SecretScreen != nil {
		screen = r.SecretScreen()
	} else {
		var err error
		screen, err = tcell.NewScreen()
		if err != nil {
			return "", fmt.Errorf("create service selector: %w", err)
		}
	}
	return selectSecretService(screen, serviceSecretNames)
}

func (r *Runner) storeServiceSecret(ctx context.Context, service, sandboxName, token string, force bool) int {
	var value []byte
	if token != "" {
		value = []byte(token)
	} else {
		read, err := r.readServiceSecret()
		if err != nil {
			r.error(err)
			return 2
		}
		value = read
	}
	defer clear(value)
	scope := sdk.SecretScopeGlobal
	if sandboxName != "" {
		scope = sdk.SecretScopeSandbox
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	secrets := sdk.Secrets(client)
	var summary sdk.ServiceSecret
	if force {
		summary, err = secrets.Set(ctx, service, scope, sandboxName, value)
	} else {
		creator, ok := sdk.SecretCreation(client)
		if !ok {
			r.error(errors.New("create-only service-secret storage is not supported by this client; refusing a non-atomic write"))
			return 1
		}
		summary, err = creator.Create(ctx, service, scope, sandboxName, value)
	}
	if err != nil {
		r.error(err)
		var sdkErr *sdk.Error
		if errors.As(err, &sdkErr) && sdkErr.Code == "already_exists" {
			return 2
		}
		return 1
	}
	displayScope := string(summary.Scope)
	if summary.SandboxName != "" {
		displayScope += " " + summary.SandboxName
	}
	_, _ = fmt.Fprintf(r.Out, "Stored %s secret (%s) in host keychain\n", summary.Service, displayScope)
	return 0
}

func (r *Runner) serviceSecretOAuthSet(ctx context.Context, service, sandboxName, token, ref, command string) int {
	if service != openAIService || sandboxName != "" || token != "" || ref != "" || command != "" {
		r.error(fmt.Errorf("%s is supported only for global %s credentials and cannot be combined with value/source flags", oauthFlag, openAIService))
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if err := sdk.Accounts(client).Login(ctx, openAIService); err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Stored %s OAuth credentials in host keychain\n", openAIService)
	return 0
}

func (r *Runner) readServiceSecret() ([]byte, error) {
	if file, ok := r.In.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		if _, err := fmt.Fprint(r.Err, "Secret: "); err != nil {
			return nil, fmt.Errorf("write secret prompt: %w", err)
		}
		value, err := term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(r.Err)
		if err != nil {
			return nil, fmt.Errorf("read secret: %w", err)
		}
		if len(value) == 0 || len(value) > 8192 {
			clear(value)
			return nil, errors.New("secret must be 1 to 8192 bytes")
		}
		return value, nil
	}
	value, err := io.ReadAll(io.LimitReader(r.In, 8193))
	if err != nil {
		clear(value)
		return nil, fmt.Errorf("read secret from stdin: %w", err)
	}
	if len(value) > 8192 {
		clear(value)
		return nil, errors.New("secret exceeds the 8192-byte limit")
	}
	value = bytes.TrimSuffix(bytes.TrimSuffix(value, []byte("\n")), []byte("\r"))
	if len(value) == 0 || bytes.ContainsAny(value, "\r\n") {
		clear(value)
		return nil, errors.New("secret input must contain one non-empty line")
	}
	return value, nil
}

func validServiceSecret(service string) bool {
	if validMCPSecretService(service) {
		return true
	}
	for _, candidate := range serviceSecretNames {
		if service == candidate {
			return true
		}
	}
	return false
}

func normalizeServiceSecret(service string) string {
	if strings.Contains(service, ":") {
		return service
	}
	return strings.ToLower(service)
}

func validMCPSecretService(service string) bool {
	parts := strings.Split(service, ":")
	return len(parts) == 3 && parts[0] == "mcp" && validMCPSecretPart(parts[1], true) && validMCPSecretPart(parts[2], false)
}

func validMCPSecretPart(value string, allowDot bool) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, char := range value {
		if !validMCPSecretCharacter(char, allowDot) || index == 0 && (char == '_' || char == '-' || char == '.') {
			return false
		}
	}
	return true
}

func validMCPSecretCharacter(char rune, allowDot bool) bool {
	if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' {
		return true
	}
	return allowDot && char == '.'
}

func (r *Runner) serviceSecretRemove(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{sandboxFlag: true, oauthFlag: false, globalFlag: false, forceFlag: false, "-f": false})
	fs := flag.NewFlagSet("secret rm", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	sandboxName := fs.String("sandbox", "", "scope the secret to one sandbox")
	oauth := fs.Bool("oauth", false, "remove host-side OpenAI OAuth credentials")
	global := fs.Bool("global", false, "deprecated: remove global credentials")
	force := fs.Bool("force", false, "delete without confirmation prompt")
	fs.BoolVar(force, "f", false, "delete without confirmation prompt")
	if code, done := r.parseFlagsOrFail("secret rm", fs, args); done {
		return code
	}
	if message, code := secretRemovalArgumentError(fs.NArg(), *global, *sandboxName); code != 0 {
		_, _ = fmt.Fprintln(r.Err, message)
		return code
	}
	service := openAIService
	if fs.NArg() == 2 {
		*sandboxName = fs.Arg(0)
		service = normalizeServiceSecret(fs.Arg(1))
		_, _ = fmt.Fprintf(r.Err, "warning: the positional sandbox scope is deprecated and will be removed in a future release; use rsbx secret rm %s --sandbox %s\n", sanitizeTerminalText(service), sanitizeTerminalText(*sandboxName))
	} else if fs.NArg() == 1 {
		service = normalizeServiceSecret(fs.Arg(0))
	}
	if *global {
		_, _ = fmt.Fprintln(r.Err, "warning: --global is deprecated; global is now the default for service secrets; omit --global, use --sandbox to target one sandbox, or use --all-sandboxes with --registry")
	}
	if fs.NArg() == 0 && !*oauth {
		return r.serviceSecretRemoveInteractive(ctx, *sandboxName, *global)
	}
	if *oauth && (service != openAIService || *sandboxName != "") {
		r.error(fmt.Errorf("%s is supported only for global %s credentials", oauthFlag, openAIService))
		return 2
	}
	return r.removeNamedServiceCredentials(ctx, service, *sandboxName, *oauth, *force)
}

func secretRemovalArgumentError(positionals int, global bool, sandboxName string) (string, int) {
	if global && sandboxName != "" {
		return "error: cannot specify both --global and --sandbox\n  try: rsbx secret rm --help", 1
	}
	if positionals > 1 && (global || sandboxName != "") {
		return "error: accepts at most 1 SERVICE argument when --global or --sandbox is used\n  try: rsbx secret rm --help", 1
	}
	if positionals > 2 {
		return fmt.Sprintf("usage: rsbx secret rm SERVICE [--sandbox NAME] [%s] [--force]", oauthFlag), 2
	}
	return "", 0
}

func (r *Runner) removeNamedServiceCredentials(ctx context.Context, service, sandboxName string, oauth, force bool) int {
	scope := sdk.SecretScopeGlobal
	if sandboxName != "" {
		scope = sdk.SecretScopeSandbox
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	present, servicePresent, err := namedServiceCredentialPresent(ctx, client, service, scope, sandboxName, oauth)
	if err != nil {
		r.error(err)
		return 1
	}
	if !present {
		_, _ = fmt.Fprintf(r.Err, "error: no secret found for service %q in scope %q\n", service, serviceCredentialScopeLabel(scope, sandboxName))
		return 1
	}
	if servicePresent {
		if err := writeNamedServiceRemovalCandidate(r.Out, service, serviceCredentialScopeLabel(scope, sandboxName)); err != nil {
			r.error(err)
			return 1
		}
	}
	confirmed, code := r.confirmSecretRemoval(fmt.Sprintf("%s credentials", service), force)
	if code != 0 {
		return code
	}
	if !confirmed {
		return 0
	}
	if oauth {
		return r.removeNamedOAuthCredential(ctx, client, openAIService)
	}
	return r.removeNamedServiceValue(ctx, client, service, scope, sandboxName)
}

func namedServiceCredentialPresent(ctx context.Context, client sdk.Client, service string, scope sdk.SecretScope, sandboxName string, oauthOnly bool) (bool, bool, error) {
	servicePresent := false
	var err error
	if !oauthOnly {
		servicePresent, err = serviceCredentialPresent(ctx, client, service, scope, sandboxName)
		if err != nil {
			return false, false, err
		}
	}
	present := servicePresent
	if oauthOnly || service == openAIService && scope == sdk.SecretScopeGlobal {
		oauthPresent, statusErr := sdk.AccountStatus(client).Status(ctx, openAIService)
		if statusErr != nil {
			return false, false, fmt.Errorf("check %s OAuth credentials before removal: %w", openAIService, statusErr)
		}
		present = present || oauthPresent
	}
	return present, servicePresent, nil
}

func writeNamedServiceRemovalCandidate(out io.Writer, service, scope string) error {
	writer := tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
	if _, err := fmt.Fprintln(writer, "SCOPE\tSERVICE\tSECRET"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "%s\t%s\t\n", sanitizeTerminalText(scope), sanitizeTerminalText(service)); err != nil {
		return err
	}
	return writer.Flush()
}

func serviceCredentialScopeLabel(scope sdk.SecretScope, sandboxName string) string {
	if scope == sdk.SecretScopeSandbox {
		return sandboxName
	}
	return globalScopeLabel
}

func (r *Runner) removeNamedOAuthCredential(ctx context.Context, client sdk.Client, service string) int {
	removed, err := sdk.Accounts(client).Logout(ctx, service)
	if err != nil {
		r.error(err)
		return 1
	}
	if removed {
		_, _ = fmt.Fprintf(r.Out, "Removed %s OAuth credentials\n", service)
	} else {
		_, _ = fmt.Fprintf(r.Out, "No %s OAuth credentials stored\n", service)
	}
	return 0
}

func (r *Runner) removeNamedServiceValue(ctx context.Context, client sdk.Client, service string, scope sdk.SecretScope, sandboxName string) int {
	removed, err := sdk.Secrets(client).Remove(ctx, service, scope, sandboxName)
	if err != nil {
		r.error(err)
		return 1
	}
	if service == openAIService && scope == sdk.SecretScopeGlobal {
		var code int
		removed, code = r.removeOpenAIGlobalOAuth(ctx, client, service, removed)
		if code != 0 {
			return code
		}
	}
	if removed {
		_, _ = fmt.Fprintf(r.Out, "Removed %s credentials\n", sanitizeTerminalText(service))
	} else {
		_, _ = fmt.Fprintf(r.Out, "No %s credentials stored\n", sanitizeTerminalText(service))
	}
	return 0
}

func serviceCredentialPresent(ctx context.Context, client sdk.Client, service string, scope sdk.SecretScope, sandboxName string) (bool, error) {
	items, err := sdk.Secrets(client).List(ctx)
	if err != nil {
		return false, fmt.Errorf("list service credentials before removal: %w", err)
	}
	for _, item := range items {
		if item.Service == service && item.Scope == scope && item.SandboxName == sandboxName {
			return true, nil
		}
	}
	return false, nil
}

func (r *Runner) removeOpenAIGlobalOAuth(ctx context.Context, client sdk.Client, service string, apiKeyRemoved bool) (bool, int) {
	oauthRemoved, err := sdk.Accounts(client).Logout(ctx, openAIService)
	if err == nil {
		return apiKeyRemoved || oauthRemoved, 0
	}
	if apiKeyRemoved {
		_, _ = fmt.Fprintf(r.Err, "Removed %s API key, but OAuth credential removal failed: %v\n", service, err)
	} else {
		r.error(err)
	}
	return apiKeyRemoved, 1
}

func (r *Runner) serviceSecretRemoveInteractive(ctx context.Context, sandboxFilter string, globalOnly bool) int {
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
	choices := buildSecretRemovalChoices(inventory, sandboxFilter, globalOnly)
	if len(choices) == 0 {
		_, _ = fmt.Fprintln(r.Out, "No supported credentials stored")
		return 0
	}
	screenFactory := r.SecretScreen
	var screen tcell.Screen
	if screenFactory == nil {
		screen, err = tcell.NewScreen()
		if err != nil {
			r.error(fmt.Errorf("create credential selector: %w", err))
			return 1
		}
	} else {
		screen = screenFactory()
	}
	selected, err := selectSecretRemovalChoice(screen, choices)
	if err != nil {
		r.error(err)
		return 1
	}
	if selected < 0 || selected >= len(choices) {
		_, _ = fmt.Fprintln(r.Out, "Removal canceled")
		return 0
	}
	choice := choices[selected]
	return r.removeSecretChoice(ctx, client, choice)
}

func (r *Runner) removeSecretChoice(ctx context.Context, client sdk.Client, choice secretRemovalChoice) int {
	switch {
	case choice.service != "":
		removed, err := sdk.Secrets(client).Remove(ctx, choice.service, choice.scope, choice.sandbox)
		if err != nil {
			r.error(err)
			return 1
		}
		if removed {
			_, _ = fmt.Fprintf(r.Out, "Removed %s\n", choice.label)
		}
	case choice.registry != "":
		response, err := client.RegistryCredentials().Logout(ctx, sdk.RegistryLogoutRequest{
			Registry: choice.registry, Scope: choice.regScope, SandboxName: choice.sandbox,
		})
		if err != nil {
			r.error(err)
			return 1
		}
		if response != nil && response.Removed {
			_, _ = fmt.Fprintf(r.Out, "Removed %s\n", choice.label)
		}
	case choice.provider != "":
		removed, err := sdk.Accounts(client).Logout(ctx, choice.provider)
		if err != nil {
			r.error(err)
			return 1
		}
		if removed {
			_, _ = fmt.Fprintf(r.Out, "Removed %s\n", choice.label)
		}
	}
	return 0
}

//nolint:gocognit,gocyclo,cyclop,funlen // one command renders two credential types and three formats.
func (r *Runner) serviceSecretList(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("secret ls", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	global := fs.Bool("global", false, "show only global secrets")
	fs.BoolVar(global, "g", false, "show only global secrets")
	sandbox := fs.String("sandbox", "", "show only secrets scoped to one sandbox")
	service := fs.String("service", "", "filter by service name")
	quiet := fs.Bool("quiet", false, "show only secret names")
	fs.BoolVar(quiet, "q", false, "show only secret names")
	if code, done := r.parseFlagsOrFail("secret ls", fs, args); done {
		return code
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx secret ls [--format table|json|yaml]")
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
	out := make([]serviceSecretOutput, 0, 4)
	items, err := sdk.Secrets(client).List(ctx)
	if err != nil {
		var sdkErr *sdk.Error
		if !errors.As(err, &sdkErr) || sdkErr.Code != "unsupported" {
			r.error(err)
			return 1
		}
	}
	for _, item := range items {
		out = append(out, serviceSecretOutput{Type: "service", Service: item.Service, Scope: string(item.Scope), SandboxName: item.SandboxName, State: "(stored)"})
	}
	if lister, ok := sdk.RegistryCredentialList(client); ok {
		registries, regErr := lister.ListRegistryCredentials(ctx)
		if regErr != nil {
			r.error(regErr)
			return 1
		}
		for _, item := range registries {
			out = append(out, serviceSecretOutput{Type: "registry", Service: item.Registry, Username: item.Username, Scope: item.Scope, SandboxName: item.SandboxName, State: "(stored)"})
		}
	}
	out = filterSecretList(out, *global, *sandbox, *service)
	if *quiet {
		for _, item := range out {
			if _, err := fmt.Fprintln(r.Out, item.Service); err != nil {
				r.error(err)
				return 1
			}
		}
		return 0
	}
	switch selected {
	case listFormatTable:
		if len(out) == 0 {
			_, _ = fmt.Fprintln(r.Out, "No secrets stored")
			return 0
		}
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "TYPE\tSERVICE\tUSERNAME\tSCOPE\tSANDBOX\tSECRET")
		for _, item := range out {
			sandbox := item.SandboxName
			if sandbox == "" {
				sandbox = globalScopeLabel
			}
			username := item.Username
			if username == "" {
				username = "-"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", item.Type, item.Service, username, item.Scope, sandbox, item.State)
		}
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(out)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(out); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}

func filterSecretList(items []serviceSecretOutput, global bool, sandbox, service string) []serviceSecretOutput {
	filtered := make([]serviceSecretOutput, 0, len(items))
	for _, item := range items {
		if global && item.Scope != string(sdk.SecretScopeGlobal) && item.Scope != string(sdk.RegistryScopeHostOnly) {
			continue
		}
		if sandbox != "" && item.SandboxName != sandbox {
			continue
		}
		if service != "" && !strings.EqualFold(item.Service, service) {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

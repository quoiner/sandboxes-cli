# sandboxes-cli

Status: pre-alpha.

## Import path migration

The canonical Go module path is now `github.com/rheic/sandboxes-cli` (previously `github.com/quoiner/sandboxes-cli`). Update imports and `go.mod` requirements when moving to a release that includes this change. The old module path is not kept as a compatibility alias.

Command-line and terminal client. Uses sandboxes-go-sdk; does not import daemon
internals. The read-only dashboard uses `github.com/gdamore/tcell/v3` as its
terminal runtime. Bubble Tea is not used. TUI remains a thin view/input layer;
non-interactive commands retain stable text and JSON output.

## Migrating from `qsbx`

The executable is now named `rsbx`. Update scripts, aliases, CI jobs, and
package-manager references from `qsbx` to `rsbx`, then regenerate shell
completions with `rsbx completion <shell>`. The daemon socket and sandbox data
are unchanged. No `qsbx` compatibility binary or Docker-owned `sbx` alias is
installed.

## Environment files

`rsbx env plan [PATH...]` renders a read-only, redacted preview. `rsbx env
create [PATH...]` applies the currently supported local subset and creates a
sandbox without attaching. The subset includes agent, name, workspace mounts,
ports, environment variables, and CPU/memory options. The command asks for
approval on a terminal; non-interactive use must pass `--force`, which approves
only that invocation. Environment values are sent to the local daemon but are
never printed by the CLI.

`rsbx env exec [PATH...] -- COMMAND [ARG...]` runs a command in a matching
existing environment sandbox and starts it if stopped. Create a missing
sandbox first. `env run` and `env rm`, as well as kits, credentials, host
commands, and MCP declarations, are not implemented yet and fail closed.
`env apply` and `env ls` are not Docker `sbx` commands; Rheic keeps the upstream
`create` name for provisioning.

## Commands

```sh
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" run shell .
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" run shell . /path/to/docs:ro
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" run --detach --name dev --cpus 2 --memory 2g --publish 8080:3000 shell .
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" run --name dev -- -c 'printf reattach'
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" run --rm --name dev -- -c 'exit 0'
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" exec -it dev /bin/sh
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" exec -e FOO=bar --env-file .env -u 1000:1001 dev env
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" cp ./file.txt dev:/tmp/file.txt
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" cp dev:/tmp/result.txt ./result.txt
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" create --name dev shell . /docs:ro --publish 8080:3000
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" create shell .   # auto-generated name
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" ports dev
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" ls
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" ls --format json
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" ls -q
rsbx tui
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" get <name-or-id>
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" start one two
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" stop one two
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" rm [--force] one two
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" rm --all --force
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" prune --dry-run
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" prune --dry-run --filter until=168h
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" prune --force
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" diagnose
rsbx completion bash > /tmp/rsbx-completion.bash
source /tmp/rsbx-completion.bash
rsbx --socket "$HOME/.sandboxes/sandboxesd.sock" wait <operation-id>
rsbx secret set --registry ghcr.io --username <registry-user>
rsbx secret set openai --sandbox dev          # hidden prompt; value stays in host keychain
rsbx secret set openai --oauth                # OpenAI account OAuth on the host
rsbx secret import --all
rsbx secret ls
rsbx secret rm openai --sandbox dev
rsbx secret rm openai --oauth
rsbx settings ls
rsbx settings set dns.upstream 1.1.1.1:53
rsbx settings set policy.profile balanced
rsbx attach dev
rsbx kit inspect examples/kits/codex-go.yaml
rsbx run --kit examples/kits/codex-go.yaml
```

The `rsbx tui` dashboard draws the Rheic ember mark directly in the terminal,
with the organization name, brand colors, and sandbox status. The scalable SVG
mark is in `assets/rheic-mark.svg`.

`rsbx create` mirrors the Docker grammar `create AGENT [PATH...]` with optional
`--name NAME`; a missing PATH creates a mountless sandbox, and PATHs accept the
`:ro` suffix. The legacy `create NAME` and repeated `--workspace` forms remain
supported. `rsbx run` creates a sandbox (or reuses `--name`), starts it if needed, and
attaches an interactive shell. The default workspace is the current directory;
multiple PATH arguments may follow the agent, with an optional `:ro` suffix.
`--deny-write PATH` adds a read-only subpath mount, so a writable parent can
hold a protected child. `--detach` creates and starts without attaching
and prints the sandbox ID. `--cpus`/`--memory` apply only when creating;
reusing an existing sandbox warns and keeps its resources. `-e/--env` and
`--env-file` add session env overrides. `--rm` removes the sandbox after the
session (rejected with `--detach`). `kimi` retains its existing Rheic extension
path. The Docker v0.50.1 built-in set is exposed through
`rsbx agents list`: `claude`, `codex`, `copilot`, `cursor`, `devin`,
`docker-agent`, `droid`, `gemini`, `kiro`, `opencode`, and `shell`. The nine
entries use Docker's published multi-platform images pinned by manifest digest
and select the dedicated guest Docker profile. Their status remains preview
until per-agent authentication and VM lifecycle acceptance passes. `rsbx run`
accepts preview agents and preserves Docker's argument rule:
agent flags after `--` extend the default command, while a bare subcommand or
prompt replaces it. `dsh` remains a Rheic preview extension; `cline` is
unsupported. The embedded registry is `internal/agent/registry.yaml`. Multiple
workspaces are supported; a
`:ro` suffix mounts a directory read-only. `--publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6]`
may be repeated when creating, with loopback `HOST_IP` limited to `127.0.0.1` and
`::1` (IPv6 uses brackets, e.g. `[::1]:8080:80/tcp6`); `rsbx ports SANDBOX`
lists the stored bindings; `ports --publish ...` / `--unpublish ...` change them
live; omitting `HOST_PORT` allocates an ephemeral host port on the selected
loopback IP.
`--allow-network CIDR[:PORT]` and `--deny-network CIDR[:PORT]` (optional `udp:`
prefix) add create-time IPv4 egress rules; the default remains deny.
`--policy-profile deny-all|balanced|sbx-compat` selects an egress preset
(balanced: 80/443 + DNS; sbx-compat: all IPv4 network); the global default is
`deny-all` and settings can change it. `rsbx policy ls [SANDBOX]` lists global
and sandbox rules with `rule_id`, scope, action, protocol, target and port.
`policy allow|deny|rm network [--sandbox NAME] TARGET` accepts an IPv4 CIDR or
a domain (`example.com`, `*.example.com`, `**.example.com`, single-label
`?`/`[]` globs), with an optional `:PORT`; deny wins across scopes and global
changes are applied live to running sandboxes. Domain rules require a DNS
upstream and resolve only allowlisted names; a domain rule is enforced after a
DNS answer is bound to its IPs. `policy check network` evaluates CIDR or domain
targets (exit 0 allow, 1 deny). `reset`, `refresh`, approvals, HTTP methods and
filesystem rules are not implemented. TCP and UDP are supported with explicit
or ephemeral host ports; an occupied host port is rejected at create and
dynamic updates reconcile gvproxy's forwarders without restarting the VM.
Loopback IPv4/IPv6 bindings are supported; public bindings are rejected.
Local kits (`--kit FILE_OR_DIR`) can set agent, image, profile and mounts. A
Docker Kits v2 directory is read from `spec.yaml` (or `spec.yml`). Its sandbox
envelope and OAuth declaration fields are accepted for
the implemented subset; unrecognized fields, mixins, remote references,
signatures and unsupported runtime features still fail closed. A
`workspace.seed` git URL is cloned once into the host cache with hooks disabled
and mounted as the workspace; signatures and MCP allowlists still fail closed. Reusing a `--name` with an
explicitly different workspace set/mode fails instead of silently ignoring the
mounts.
`rsbx exec -i/-t/-it` supports stdin, separate stdout/stderr, terminal size and
resize, and returns the guest exit status. Missing commands exit 127, non-executable
paths 126, sandbox/runtime errors 125, and signal exits use 128+signal
(`137` SIGKILL, `143` SIGTERM). Host-to-guest interactive signal forwarding is
not implemented. `-e/--env KEY=VALUE` and repeated
`--env-file FILE` add explicit environment overrides; `-e NAME` copies exactly
that one host variable when set (unset names are skipped). No other host
variables are read. The last duplicate wins. `-u/--user` accepts
numeric `uid[:gid]` or a guest user/group name (`root`, `nobody:nogroup`); a
bare uid keeps the image/process GID. Names are resolved by a short root probe
inside the guest using `id` and `/etc/group`, and unknown names fail closed.
Environment values
can be visible in host process arguments when passed with `-e`; do not put
secrets in argv (prefer a bounded, permission-restricted env file).

`rsbx attach [--shell] SANDBOX` starts a stopped sandbox and opens its agent
session. `rsbx settings ls|get|set|unset` manages
`~/.config/rheic/settings.toml` (`dns.upstream`, `policy.profile`,
`defaults.cpus`, `defaults.memory_mib`, `sandbox.disk.dockerVolume`); DNS and
daemon-owned consumers need a daemon restart. `rsbx secret` stores service API
keys and registry credentials in the host keychain. Service secret values are
not written to SQLite, logs or argv. `${secret:service}` environment references
are rejected because guest processes can read environment values. Migrate
scripts to a supported host proxy route; the proxy keeps the real credential on
the host and adds it only to requests sent to a fixed provider host.

`rsbx cp` copies regular files and directory trees in either direction; exactly
one side is `SANDBOX:PATH` with an absolute guest path. A guest destination
ending in `/` or an existing guest directory, and an existing host directory,
are used as containers.
Archives are streamed through an exec session; guest-to-host extraction uses
`os.Root`, rejects traversal/symlink/hardlink/special entries, and bounds entry
count (100000) and size (4 GiB). Source symlinks are rejected by default; `-L/--follow-link` follows source
symlinks, including nested file and directory links. If the local source is
inside a sandbox workspace, no followed link may escape that workspace
(including when the workspace itself is reached through a symlink); cycles and
special files fail closed.

`rsbx diagnose` checks the socket path, calls `List` with a five-second deadline,
and reports sandbox counts; `--json` emits the same report for automation. It
does not diagnose containerd, image, gateway, or credential state yet.
`rsbx stop`/`start`, `rm` and `prune` accept `--format table|json|yaml` and
`--json`; structured output carries operation records (or sandbox candidates
for `prune --dry-run`).

`rsbx ls` retrieves all pages; `--limit` controls the page size. `--format`
accepts `table`, `json` or `yaml`; `--json` is the JSON shorthand, and `-q`
prints names only. JSON/YAML include `name`, `id`, `agent`, `status`, `image`,
`agent`, `status`, `last_used_at`, `workspaces`, `detached`, `cpus`, `memory_mib`,
`generation`, `created_at` and `updated_at`. The table is Docker-like:
`SANDBOX AGENT STATUS PORTS WORKSPACE CREATED`.
The local store does not record an agent yet, so `agent` is empty; Docker's
`last_used_at` and `detached` fields are not emitted. `rsbx get` resolves a name
or ID. `stop`/`start`/`rm` accept multiple names; `rm --all --force` removes every
sandbox after the explicit force flag. `rm` and `prune` require a
terminal confirmation unless `--force` is passed; `prune` removes stopped
sandboxes only, with `--dry-run` to preview and `--filter until=TIMESTAMP|DURATION`
to select sandboxes stopped before that point (RFC 3339, Unix seconds or a
non-negative Go duration relative to now). `rsbx wait` returns a nonzero exit
status when the operation finishes in a failed state.

`rsbx secret set --registry` prompts for the password without echo. For automation, pipe a
token through stdin with `--password-stdin`; never pass it as an argument or
environment variable. Credentials are stored in the host OS credential vault
with host-only scope by default. `--all-sandboxes` and `--sandbox NAME` store
separate scoped entries. `rsbx secret rm --registry` removes the selected entry.
Without `--all-sandboxes` or `--sandbox NAME`, it removes both host-only and
all-sandboxes entries for that registry. Registry removals prompt in a terminal;
pass `--force`/`-f` for automation. `secret rm` also accepts `remove`, `delete`,
and `unset`; `secret ls` accepts the `list` alias and Docker-style filters.
`rsbx secret rm --all` removes all currently inventoried service secrets, registry
credentials, and Docker/OpenAI account tokens across scopes after confirmation
(or with `--force`). A failure during deletion can leave a partial result.
Custom-secret storage is not implemented and is excluded; the command prints
that limitation. Running `rsbx secret rm` without a name opens an interactive
selector for currently inventoried service, registry, and Docker/OpenAI account
credentials; Enter removes the highlighted item and `q` cancels.
Like Docker `sbx`, `rsbx secret rm openai` removes both the global OpenAI API
key and host OAuth session. Use `--oauth` to remove only OAuth; `--sandbox`
removes only that sandbox's API key.

Setting a service secret uses an atomic create-only RPC and refuses to replace
an existing value. Pass `--force`/`-f` for an explicit overwrite. Older daemons
that lack this RPC fail closed with `Unimplemented`.
Omit the service name in an interactive terminal to choose from the supported
providers; noninteractive callers must name the service explicitly.

Service secrets can also use a host-side dynamic source:

```sh
rsbx secret set anthropic --ref 'op://Work/Anthropic/credential'
rsbx secret set openai --ref 'arn:aws:secretsmanager:us-west-2:123456789012:secret:openai-api-key' --refresh 30m
rsbx secret set github --command 'gh auth token' --refresh on-demand
```

The authenticated `op` or `aws` CLI must be available to the daemon on the
host. Rheic stores the reference or command in the host credential vault and
resolves it only while the host proxy needs the credential; the guest receives
only the existing proxy placeholder. Commands run through the host shell from a
fresh temporary directory, with a 30-second deadline, bounded output and
process-tree cleanup. They execute with the daemon user's host privileges and
are not confined from reading host files; use only commands you trust, and
keep helper files and the host temp directory outside writable sandbox mounts.
The daemon uses an environment allowlist; `OP_ACCOUNT` and `AWS_PROFILE` are
captured when the source is registered. The default cache duration is 55 minutes;
`--refresh on-demand` resolves for each proxied credential use. `--no-verify`
stores a source without resolving it during setup. `--show-error` can expose
provider stderr during initial verification and may print sensitive information.
Custom-secret placeholders remain unsupported.

Registry credentials previously managed with `rsbx login --registry` and
`rsbx logout --registry` are now managed with `rsbx secret set --registry`,
`rsbx secret ls` and `rsbx secret rm --registry`; existing keychain entries do
not need to be moved, but entries created before the index was introduced are
not listed until they are re-saved.

`rsbx secret set openai --oauth` starts the OpenAI/Codex PKCE flow on the host
and stores access, refresh, and ID tokens in the host credential vault. The
registered loopback callback uses `127.0.0.1:1455` with `1457` as a fallback.
Use `rsbx secret rm openai --oauth` to remove the OAuth record and request
best-effort upstream revocation. For clients that accept a bearer token through
`OPENAI_API_KEY`, configure the explicit host broker reference when creating a
sandbox: `rsbx run --env 'OPENAI_API_KEY=${oauth:openai}' ...`. The guest gets
only a placeholder; the daemon refreshes and injects the host token on requests
to `api.openai.com`. The built-in OpenAI OAuth route is supported. Generic kit OAuth declarations
are represented in the API contract, but custom token-endpoint interception and
credential-file setup are not enabled by this daemon yet.

`rsbx run codex` uses host credentials before starting the agent. An explicit
`OPENAI_API_KEY` or `OPENAI_BASE_URL` is left to the caller. Otherwise, the CLI
checks secret metadata (never secret values) and uses a stored OpenAI API key
through the service proxy when one applies to the selected sandbox. If no API
key applies, it checks the host OAuth account, starts login when needed, and
passes only the OAuth proxy reference into Codex. This selection is limited to
the built-in Codex run path; `create` does not start an interactive login.

A local kit can select the built-in OpenAI host OAuth flow:

```yaml
spec:
  credentials:
    - service: openai
      oauth:
        resourceHosts: [api.openai.com]
```

`rsbx run --kit FILE` checks host credential status and starts the host login
flow if needed. The OpenAI issuer, token endpoint, and resource policy are fixed
by the daemon; a kit cannot override them. Generic Docker v2 OAuth declarations
are parsed and transported by CLI/API, but the daemon still rejects them until
host TLS interception, resource routing, guest credential-file setup, and
per-sandbox vault lifecycle are implemented.

`rsbx login` and `rsbx logout` are reserved for Docker account authentication,
using the same Docker public device-flow client as Docker CLI and Docker
Sandboxes. Login starts device authorization at Docker, opens the browser,
waits for approval, exchanges the grant for a Docker Hub PAT, and stores the
credentials in the native host vault. No Rheic OAuth registration is needed.
For headless login, use `rsbx login --username USER --password-stdin` and pipe a
Docker Hub password or personal access token into stdin. The daemon validates it
with Docker Hub before storing it; the token is never accepted as a command-line
argument, printed, or written into the OAuth account record.
Existing Docker Hub registry entries cause login to fail instead of being
overwritten. Authenticated sandbox registry pulls are not connected to the
guest network path yet.

`rsbx logout` asks before stopping running local sandboxes. `--force`/`-f` skips
the prompt, stops only sandboxes owned by the selected local daemon, then removes
the OAuth-owned Docker Hub credentials and requests provider token revocation.
Registry credentials created separately with `rsbx secret set` are preserved.
If the provider cannot revoke a refresh token, the CLI reports that local
credentials were removed but remote revocation did not complete.

Registry secret storage does not currently validate credentials with the
registry or enable authenticated pulls from a sandbox. Registry broker and
policy enforcement are still under implementation; the command says so on
success.

`SANDBOXES_SOCKET` can replace the `--socket` flag. Rheic commands and examples use `rsbx`; `sandboxes` is only the repository name. Docker Sandboxes commands are written as `sbx ...` only when explicitly discussing Docker's original product. A Rheic `sbx` compatibility alias is not installed by default; it requires that `command -v sbx` be empty and explicit user consent.

## Development

Requires Go 1.27.

```sh
make test
make build
```

For local development with the sibling daemon checkout and `modules/go.work`,
`make dev-bundle` builds `dist/rsbx` and `dist/sandboxesd`. Start the daemon
in a terminal with `dist/sandboxesd`, then use `dist/rsbx` in another terminal.
This bundle currently starts the state-only daemon: it does not install a
service, configure a VM runtime, or provide account OAuth. It is not a release
package; releases must build against tagged dependencies.

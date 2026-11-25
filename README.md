# agent-leash

**8 guardrails for running Claude Code and Codex unattended.**
One Python file. Zero dependencies. Works as a Claude Code hook, a Codex hook and a git pre-commit hook.

Most hook packs stop `rm -rf /`. That's guardrail 1 of 8. The expensive failures of an agent left alone overnight are different: it burns the budget, it re-runs a deploy whose result it never saw, and it tells you "done" while the tests are red. agent-leash covers those too.

```bash
git clone https://github.com/PrabalParihar/agent-leash ~/.agent-leash-src && python3 ~/.agent-leash-src/leash.py install
```

That copies `leash.py` to `~/.agent-leash/`, writes a default `config.json`, and registers the hooks in `~/.claude/settings.json` and `~/.codex/hooks.json` (Codex asks you to trust it once in `/hooks`). Add `--git` inside a repo to also install the pre-commit gate.

## The 8 guardrails

| # | Rule | What agent-leash does |
|---|---|---|
| 1 | Match command strings and confine paths | Blocks writes and deletes outside the project root (`/tmp` and `/var/tmp` are allowed by default), `rm -rf` on `/`, `~`, `..` or the repo itself, deletes whose target is an unresolved `$VAR`, `curl \| bash`, disk wipes, `terraform destroy`, `DROP TABLE` through a DB client, `git reset --hard`, `git clean -f`, `git checkout .` |
| 2 | Keep real keys away from the agent | Blocks reading `.env*`, `~/.ssh`, `~/.aws`, `*.pem`, keystores; `printenv`/`env` dumps; `--private-key` on the command line; and any write, edit, patch or commit that contains a literal API key, token or 64-hex private key |
| 3 | Short, locked state changes | Session state is written atomically (`write tmp → rename`) to `~/.agent-leash/state/` |
| 4 | Workers get leases | Each session gets a lease (default 120 min). After it expires every tool call is refused: stop, report, start fresh |
| 5 | Unclear outcome = unknown, never resend | Side effects (`git push`, `npm publish`, deploys, `kubectl apply`, `cast send`, `forge script --broadcast`, `curl -X POST`…) get an intent id = command + commit. If the agent never saw the result, a retry is blocked until a human runs `leash.py resolve <id> done\|failed`. A side effect that already succeeded can't run twice |
| 6 | Reserve budget before work | Caps tool calls (400). The token and dollar budget (3M tokens or $15) is read from the Claude Code transcript and works in Claude Code only. Codex gets just the lease and the tool-call budget. No budget, no job |
| 7 | Block protected-branch pushes and `--no-verify` | Blocks pushes to `main`, `master`, `production`, `prod` and `release` (even a plain `git push` while on one of them) and `--no-verify`. The pre-commit gate re-checks staged code for secrets and runs `test_command` when one is set |
| 8 | Evidence, not the model's word | If the agent changed files, the Stop hook runs your `test_command`. Red tests = the agent is sent back to work instead of saying "done" (gives up after 3 tries and tells you not to trust it) |

Every block prints the rule id and the reason to the agent, and lands in `~/.agent-leash/audit.jsonl`.

## Configure

`~/.agent-leash/config.json` (yours, the agent can't edit it):

```json
{
  "test_command": "npm test --silent",
  "lease_minutes": 120,
  "max_tool_calls": 400,
  "max_tokens": 3000000,
  "max_usd": 15,
  "protected_branches": ["main", "master", "production", "prod", "release"],
  "allow_commands": [],
  "deny_commands": ["\\bnpm\\s+run\\s+db:seed:prod\\b"]
}
```

A repo can ship `.leash.json` to set its `test_command`, add `deny_commands` and **lower** budgets. It can never allowlist a command or raise a budget, so a cloned repo can't loosen your leash.

The agent can't edit `.claude/settings.json`, `.codex/hooks.json`, `.leash.json`, `~/.agent-leash/` or `.git/hooks/`.

## Try it without an agent

```bash
python3 ~/.agent-leash/leash.py check 'rm -rf $BUILD_DIR/'
# BLOCK (rm-unresolved-var): delete target `$BUILD_DIR/` depends on a variable; ...
python3 ~/.agent-leash/leash.py check 'rm -rf ./build'
# ALLOW
```

## Rule files for the model

`templates/CLAUDE.md` and `templates/AGENTS.md` carry the same 8 rules in plain words. Paste them into your repo so the model knows the rules before a hook has to stop it. Hooks enforce; the rule files explain.

## What it is not

- Not a sandbox. It matches the command string and confines paths. It can't see what a script does once it runs, payloads decoded at runtime, or what an MCP server does. Run unattended agents in a container or VM as well.
- Anything that can edit your user config can turn it off. Install at user level and keep the agent out of `~/.agent-leash/`.
- The token and dollar budget works in Claude Code only. It reads Claude Code's transcript, and Codex has no transcript path in its hook input, so Codex gets just the lease and the tool-call budget.

## Tests

```bash
python3 tests/test_leash.py
```

17 end-to-end tests feed real Claude Code and Codex hook JSON to `leash.py` in a throwaway git repo (40+ commands checked).

MIT licensed.

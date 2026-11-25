#!/usr/bin/env python3
"""agent-leash: 8 guardrails for running Claude Code and Codex unattended.

One zero-dependency file. Plugs into Claude Code and Codex hooks (PreToolUse,
PostToolUse, Stop) and into git pre-commit. Exit code 2 = blocked; the reason
goes to stderr so the agent sees why and can change course.

Usage:
  leash.py hook                 read a hook event (JSON) on stdin and decide
  leash.py check "<command>"    dry-run a shell command against the rules
  leash.py precommit            git pre-commit gate (secret scan + tests)
  leash.py status [session]     show budget, lease and side-effect ledger
  leash.py resolve <intent-id> done|failed   settle an "unknown" side effect
  leash.py install [--claude] [--codex] [--git] [--project DIR]
"""
import hashlib, json, os, re, shlex, subprocess, sys, time

VERSION = "0.1.0"
HOME = os.path.expanduser("~")
LEASH_HOME = os.environ.get("LEASH_HOME", os.path.join(HOME, ".agent-leash"))

DEFAULTS = {
    "protected_branches": ["main", "master", "production", "prod", "release"],
    "lease_minutes": 120,           # G4: a session's work lease
    "max_tool_calls": 400,          # G6: budget
    "max_tokens": 3000000,          # G6: summed from the Claude Code transcript
    "usd_per_million_tokens": 3.0,  # G6: rough blended price for the estimate
    "max_usd": 15.0,
    "test_command": "",             # G8: e.g. "npm test --silent" or "pytest -q"
    "test_timeout_seconds": 300,
    "max_stop_retries": 3,
    "allow_outside_root": ["/tmp", "/var/tmp"],
    "allow_commands": [],           # regexes that always pass (set by a human)
    "deny_commands": [],            # extra regexes to block
    "side_effect_patterns": [
        r"\bgit\s+push\b", r"\bnpm\s+publish\b", r"\bpnpm\s+publish\b", r"\byarn\s+npm\s+publish\b",
        r"\btwine\s+upload\b", r"\bcargo\s+publish\b", r"\bgh\s+(release\s+create|pr\s+merge)\b",
        r"\b(vercel|netlify|fly|railway)\b.*\b(deploy|up)\b|\bvercel\s+--prod\b",
        r"\bkubectl\s+(apply|rollout)\b", r"\bhelm\s+(install|upgrade)\b", r"\bterraform\s+apply\b",
        r"\bcast\s+send\b", r"\bforge\s+script\b.*--broadcast", r"\bhardhat\b.*\b(deploy|run)\b.*--network\s+(?!localhost|hardhat)",
        r"\bcurl\b.*\s-X\s*(POST|PUT|PATCH|DELETE)\b", r"\bstripe\s+\w+\s+create\b",
    ],
}

SECRET_PATH = re.compile(
    r"(^|/)(\.env(\.[\w.-]+)?|\.npmrc|\.pypirc|\.netrc|\.pgpass|\.git-credentials|id_(rsa|ed25519|ecdsa|dsa)|"
    r"credentials(\.json)?|[\w.-]+\.(pem|key|p12|pfx|keystore)|keystore/[^/]+)$|(^|/)\.(ssh|aws|gnupg|kube)(/|$)")
SECRET_PATH_OK = re.compile(r"\.env\.(example|sample|template|dist)$")
SECRET_VALUE = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
    ("OpenAI/Anthropic-style API key", re.compile(r"\bsk-(ant-|proj-)?[A-Za-z0-9_-]{24,}")),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{30,}")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("EVM private key", re.compile(r"(?i)(private[_ -]?key|pk|secret)\s*[:=]\s*[\"']?(0x)?[0-9a-f]{64}\b")),
]
GUARD_FILES = re.compile(r"(^|/)(\.claude/settings(\.local)?\.json|\.codex/(hooks\.json|config\.toml)|\.leash\.json|\.agent-leash/|\.git/hooks/)")
SYSTEM_DIRS = ("/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/opt", "/proc", "/root", "/sbin", "/sys", "/usr", "/var", "/home", "/Users", "/System", "/Library", "/Applications")

# ---------------------------------------------------------------- config/state

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def project_root(cwd):
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return os.path.realpath(r.stdout.strip())
    except Exception:
        pass
    return os.path.realpath(cwd)

def load_config(root):
    cfg = dict(DEFAULTS)
    user = load_json(os.path.join(LEASH_HOME, "config.json"), {})
    cfg.update(user)
    proj = load_json(os.path.join(root, ".leash.json"), {})
    # A repo may only tighten the rules: it can set the test command and add denies,
    # but cannot allowlist commands or raise budgets (a hostile repo could ship one).
    if proj.get("test_command") and not user.get("test_command"):
        cfg["test_command"] = proj["test_command"]
    cfg["deny_commands"] = list(cfg.get("deny_commands", [])) + list(proj.get("deny_commands", []))
    for k in ("lease_minutes", "max_tool_calls", "max_tokens", "max_usd"):
        if isinstance(proj.get(k), (int, float)):
            cfg[k] = min(cfg[k], proj[k])
    return cfg

def state_path(session):
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session or "default")
    return os.path.join(LEASH_HOME, "state", safe + ".json")

def load_state(session):
    st = load_json(state_path(session), None)
    if not st:
        st = {"session": session, "started": time.time(), "tool_calls": 0, "changed_files": [], "intents": {}, "stop_retries": 0}
    return st

def save_state(st):
    p = state_path(st["session"])
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=1)
    os.replace(tmp, p)

def audit(event):
    try:
        os.makedirs(LEASH_HOME, exist_ok=True)
        event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        with open(os.path.join(LEASH_HOME, "audit.jsonl"), "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass

# ---------------------------------------------------------------- helpers

def norm_cmd(tool_input):
    c = tool_input.get("command", "") if isinstance(tool_input, dict) else tool_input
    if isinstance(c, list):
        c = " ".join(shlex.quote(x) for x in c)
        if c.startswith("bash -lc ") or c.startswith("bash -c "):
            try:
                c = shlex.split(c)[-1]
            except ValueError:
                pass
    return str(c)

def segments(cmd):
    return [s.strip() for s in re.split(r"\|\||&&|;|\n|\|(?!\|)", cmd) if s.strip()]

def resolve(path, cwd):
    p = path.replace("${HOME}", HOME).replace("$HOME", HOME)
    if p.startswith("~"):
        p = HOME + p[1:]
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    return os.path.realpath(p)

def inside(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")

def outside_root(path, root, cfg):
    return not inside(path, root) and not any(inside(path, os.path.realpath(a)) for a in cfg["allow_outside_root"])

# ---------------------------------------------------------------- rules

def check_command(cmd, cwd, root, cfg):
    """Return (rule_id, reason) if the shell command must be blocked, else None."""
    for rx in cfg.get("allow_commands", []):
        if re.search(rx, cmd):
            return None
    for rx in cfg.get("deny_commands", []):
        if re.search(rx, cmd):
            return ("custom-deny", "matches a deny rule in your leash config: " + rx)
    low = cmd.lower()

    # G1 sandbox: destructive shapes
    if re.search(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", cmd):
        return ("fork-bomb", "fork bomb")
    if re.search(r"\b(curl|wget|iwr|invoke-webrequest)\b[^|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(bash|sh|zsh)\s+<\(\s*(curl|wget)", low):
        return ("curl-pipe-shell", "piping a download straight into a shell runs code nobody reviewed")
    if re.search(r"\b(mkfs(\.\w+)?|wipefs|fdisk|sgdisk|parted|blkdiscard)\b|\bdd\b.*\bof=/dev/(sd|nvme|disk|hd|xvd)|>\s*/dev/(sd|nvme|disk)", low):
        return ("disk-destroyer", "writes to a raw disk")
    if re.search(r"\bchmod\s+(-\w*r\w*\s+)?(-r\s+)?(777|a\+rwx|o\+w)\s+(/|~|\$home)(\s|$)", low):
        return ("chmod-broad", "world-writable permissions on a system or home directory")
    if re.search(r"\b(drop\s+(table|database|schema)|truncate\s+table|delete\s+from\s+\w+\s*(;|\"|'|$))", low) and \
       re.search(r"\b(psql|mysql|mariadb|sqlite3|cockroach|clickhouse-client|mongosh|prisma|supabase)\b", low):
        return ("sql-destructive", "destructive SQL (DROP/TRUNCATE/DELETE without WHERE) through a database client")
    if re.search(r"\b(terraform|pulumi)\s+destroy\b|\bkubectl\s+delete\s+(ns|namespace|pv|pvc|all)\b|\bdocker\s+(system|volume)\s+prune\b|\bdocker\s+compose\s+down\b.*\s-v\b|\baws\s+s3\s+(rm|rb)\b.*--(recursive|force)", low):
        return ("infra-destroy", "tears down infrastructure or data volumes")
    if re.search(r"\bprisma\s+migrate\s+reset\b|--accept-data-loss|\b(rails|rake)\s+db:(drop|reset)\b|\bdropdb\b", low):
        return ("db-reset", "resets or drops a database")

    for seg in segments(cmd):
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        while toks and (toks[0] in ("sudo", "doas", "nohup", "time", "command", "exec") or re.match(r"^\w+=", toks[0])):
            toks = toks[1:]
        if not toks:
            continue
        prog = os.path.basename(toks[0])
        if prog in ("cd", "pushd") and len(toks) > 1:
            cwd = resolve(toks[1], cwd)
            continue
        # rm -r / find -delete: only inside the project, never with unresolved variables
        if prog in ("rm", "rmdir", "shred") or (prog == "find" and ("-delete" in toks or ("-exec" in toks and "rm" in toks))):
            flags = "".join(t.lstrip("-") for t in toks[1:] if t.startswith("-") and not t.startswith("--")) + " ".join(t for t in toks if t.startswith("--"))
            recursive = prog == "find" or "r" in flags.lower() or "recursive" in flags
            raw_targets = [t for t in toks[1:] if not t.startswith("-")]
            if prog == "find":
                raw_targets = raw_targets[:1] or ["."]
            for t in raw_targets:
                if re.search(r"\$(?!HOME\b|\{HOME\})\{?\w+", t) or "`" in t or "$(" in t:
                    return ("rm-unresolved-var", f"delete target `{t}` depends on a variable; if it is empty this deletes the wrong tree. Resolve it first")
                if t in ("*", "/*", "~/*"):
                    tp = resolve(t.replace("*", ""), cwd) if t != "*" else cwd
                    if tp == root or tp in SYSTEM_DIRS or tp == HOME:
                        return ("rm-glob-root", f"wildcard delete `{t}` would wipe {tp}")
                p = resolve(t.replace("*", ""), cwd)
                if recursive and (p in SYSTEM_DIRS or p == HOME or p == root or inside(root, p)):
                    return ("rm-root", f"recursive delete of `{t}` would remove {p} (the project root or above)")
                if outside_root(p, root, cfg):
                    return ("rm-outside-project", f"delete target `{t}` resolves to {p}, outside the project ({root})")
        if prog == "git" and len(toks) > 1:
            sub = toks[1]
            rest = toks[2:]
            if sub == "push":
                forced = any(t in ("-f", "--force", "--force-with-lease") or t.startswith("--force") or t.startswith("+") for t in rest)
                names = set(re.split(r"[:+/]", " ".join(rest).replace(" ", ":")))
                hits = [b for b in cfg["protected_branches"] if b in names]
                if not [t for t in rest if not t.startswith("-")][1:]:
                    cur = git_out(["rev-parse", "--abbrev-ref", "HEAD"], cwd)
                    if cur in cfg["protected_branches"]:
                        hits = [cur]
                if forced and hits:
                    return ("git-force-push-protected", f"force-push to protected branch {hits[0]}")
                if hits:
                    return ("git-push-protected", f"pushing straight to {hits[0]} skips review (G7). Push a branch and open a PR")
            if sub == "reset" and "--hard" in rest:
                return ("git-reset-hard", "git reset --hard throws away uncommitted work. Use git stash")
            if sub == "clean" and any(re.match(r"-\w*f", t) for t in rest):
                return ("git-clean-force", "git clean -f deletes untracked files for good")
            if sub in ("checkout", "restore") and rest[-1:] == ["."]:
                return ("git-discard-all", f"git {sub} . discards every uncommitted change")
            if sub == "branch" and "-D" in rest:
                return ("git-branch-delete", "force-deletes a branch")
            if sub in ("commit",) and "--no-verify" in rest or (sub == "commit" and "-n" in rest):
                return ("git-no-verify", "--no-verify skips the pre-commit gate (G7/G8)")
            if sub == "push" and "--no-verify" in rest:
                return ("git-no-verify", "--no-verify skips the pre-push gate")

    # G2 secrets
    for m in re.finditer(r"[^\s'\"<>|;&]+", cmd):
        tok = m.group(0)
        if SECRET_PATH.search(tok) and not SECRET_PATH_OK.search(tok):
            return ("secret-file", f"touches a secret file ({tok}). Keep real keys out of the agent's reach (G2)")
    if re.search(r"(^|[;&|]\s*)(printenv|env|export\s+-p|set)\s*($|[;&|>])", cmd) or re.search(r"\bdocker\s+compose\s+config\b", low):
        return ("env-dump", "dumps every environment variable, keys included (G2)")
    if re.search(r"--private-key\s+\S+|--mnemonic\b", low):
        return ("key-on-cli", "a private key or mnemonic on the command line lands in logs and shell history (G2)")
    for name, rx in SECRET_VALUE:
        if rx.search(cmd):
            return ("secret-literal", f"command contains a literal {name} (G2)")

    # guardrail tamper
    if GUARD_FILES.search(cmd) and re.search(r"\b(rm|mv|sed\s+-i|tee|truncate|chmod|cp)\b|>", cmd):
        return ("guard-tamper", "changes the guardrail config. Only a human edits the leash")
    return None

def check_write(path, content, root, cfg):
    p = resolve(path, root)
    if GUARD_FILES.search(p):
        return ("guard-tamper", f"{path} is guardrail config. Only a human edits the leash")
    if SECRET_PATH.search(p) and not SECRET_PATH_OK.search(p):
        return ("secret-file", f"{path} is a secret file (G2)")
    if outside_root(p, root, cfg):
        return ("write-outside-project", f"{path} resolves to {p}, outside the project ({root})")
    for name, rx in SECRET_VALUE:
        if content and rx.search(content):
            return ("secret-literal", f"the new content of {path} contains a literal {name}. Read it from the environment instead (G2)")
    return None

def check_read(path, root):
    p = resolve(path, root)
    if SECRET_PATH.search(p) and not SECRET_PATH_OK.search(p):
        return ("secret-file", f"{path} is a secret file. The agent works without real keys (G2)")
    return None

def patch_files(patch):
    files, added = [], []
    for line in str(patch).splitlines():
        m = re.match(r"\*\*\* (Add|Update|Delete) File: (.+)", line) or re.match(r"\+\+\+ b/(.+)", line)
        if m:
            files.append(m.group(m.lastindex).strip())
        elif line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    return files, "\n".join(added)

def tokens_used(transcript):
    total = 0
    try:
        with open(transcript) as f:
            for line in f:
                if '"usage"' not in line:
                    continue
                try:
                    u = json.loads(line).get("message", {}).get("usage", {})
                except Exception:
                    continue
                total += sum(int(u.get(k, 0) or 0) for k in ("input_tokens", "output_tokens", "cache_creation_input_tokens"))
                total += int(u.get("cache_read_input_tokens", 0) or 0) // 10
    except Exception:
        return 0
    return total

def git_out(args, cwd):
    try:
        r = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, timeout=5)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""

def intent_id(cmd, root):
    # same command + same commit = same intent. A new commit is a new intent.
    head = git_out(["rev-parse", "HEAD"], root)
    key = root + "\0" + head + "\0" + re.sub(r"\s+", " ", cmd.strip())
    return hashlib.sha256(key.encode()).hexdigest()[:10]

# ---------------------------------------------------------------- events

def block(rule, reason, ev):
    msg = f"[agent-leash] BLOCKED ({rule}): {reason}"
    audit({"decision": "block", "rule": rule, "reason": reason, "tool": ev.get("tool_name"), "session": ev.get("session_id")})
    print(msg, file=sys.stderr)
    return 2

def pre_tool(ev, cfg, root):
    st = load_state(ev.get("session_id"))
    st["tool_calls"] += 1
    save_state(st)
    tool = ev.get("tool_name", "")
    ti = ev.get("tool_input") or {}
    cwd = os.path.realpath(ev.get("cwd") or os.getcwd())

    # G4 lease + G6 budget
    age = (time.time() - st["started"]) / 60
    if age > cfg["lease_minutes"]:
        return block("lease-expired", f"this session's {cfg['lease_minutes']}-min lease ran out ({age:.0f} min). Stop, report, and start a fresh session", ev)
    if st["tool_calls"] > cfg["max_tool_calls"]:
        return block("budget-tool-calls", f"{st['tool_calls']} tool calls > budget {cfg['max_tool_calls']}. No budget, no job (G6)", ev)
    if ev.get("transcript_path"):
        tok = tokens_used(ev["transcript_path"])
        usd = tok / 1e6 * cfg["usd_per_million_tokens"]
        if tok > cfg["max_tokens"] or usd > cfg["max_usd"]:
            return block("budget-tokens", f"~{tok:,} tokens (~${usd:.2f}) is over the budget ({cfg['max_tokens']:,} tokens / ${cfg['max_usd']}) (G6)", ev)

    if tool in ("Bash", "shell", "local_shell", "exec_command", "container.exec") or tool.lower() in ("bash", "shell"):
        cmd = norm_cmd(ti)
        hit = check_command(cmd, cwd, root, cfg)
        if hit:
            return block(*hit, ev)
        # G5: side effects get an intent id; unknown outcomes are never blindly resent
        if any(re.search(rx, cmd, re.I) for rx in cfg["side_effect_patterns"]):
            iid = intent_id(cmd, root)
            prev = st["intents"].get(iid)
            if prev and prev["status"] == "pending":
                return block("unknown-outcome", f"this side effect already ran and its outcome is unknown (intent {iid}). Check the real state, then a human runs `leash.py resolve {iid} done|failed`. Never blindly resend (G5)", ev)
            if prev and prev["status"] == "done":
                return block("duplicate-side-effect", f"this exact side effect already succeeded in this session (intent {iid}). Running it twice is how you pay twice (G5)", ev)
            st["intents"][iid] = {"cmd": cmd, "status": "pending", "at": time.time()}
            save_state(st)
            audit({"decision": "allow-side-effect", "intent": iid, "cmd": cmd, "session": ev.get("session_id")})
        return 0
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = ti.get("file_path") or ti.get("notebook_path") or ""
        content = ti.get("content") or ti.get("new_string") or ti.get("new_source") or ""
        if tool == "MultiEdit":
            content = "\n".join(e.get("new_string", "") for e in ti.get("edits", []))
        hit = check_write(path, content, root, cfg)
        return block(*hit, ev) if hit else 0
    if tool == "apply_patch":
        files, added = patch_files(norm_cmd(ti) or ti.get("input", ""))
        for f in files:
            hit = check_write(f, "", root, cfg)
            if hit:
                return block(*hit, ev)
        for name, rx in SECRET_VALUE:
            if rx.search(added):
                return block("secret-literal", f"the patch adds a literal {name} (G2)", ev)
        return 0
    if tool in ("Read", "Grep", "Glob", "NotebookRead", "view_image"):
        path = ti.get("file_path") or ti.get("path") or (ti.get("pattern") if tool == "Glob" else "") or ""
        hit = check_read(path, root) if path else None
        return block(*hit, ev) if hit else 0
    return 0

def post_tool(ev, cfg, root):
    st = load_state(ev.get("session_id"))
    tool = ev.get("tool_name", "")
    ti = ev.get("tool_input") or {}
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"):
        files = [ti.get("file_path") or ti.get("notebook_path")] if tool != "apply_patch" else patch_files(norm_cmd(ti))[0]
        for f in files:
            if f and f not in st["changed_files"]:
                st["changed_files"].append(f)
    if tool.lower() in ("bash", "shell", "local_shell", "exec_command"):
        iid = intent_id(norm_cmd(ti), root)
        if iid in st["intents"]:
            resp = ev.get("tool_response") or {}
            failed = ev.get("hook_event_name") == "PostToolUseFailure" or (isinstance(resp, dict) and resp.get("exit_code") not in (None, 0))
            st["intents"][iid]["status"] = "failed" if failed else "done"
        if re.search(r"\b(sed\s+-i|perl\s+-pi|tee|mv|cp)\b|>", norm_cmd(ti)):
            st["changed_files"].append("(shell edit)")
    save_state(st)
    return 0

def run_tests(cfg, root):
    cmd = cfg.get("test_command")
    if not cmd:
        return True, "no test_command configured"
    try:
        r = subprocess.run(cmd, shell=True, cwd=root, capture_output=True, text=True, timeout=cfg["test_timeout_seconds"])
    except subprocess.TimeoutExpired:
        return False, f"`{cmd}` timed out after {cfg['test_timeout_seconds']}s"
    out = (r.stdout + r.stderr).strip().splitlines()[-15:]
    return r.returncode == 0, f"`{cmd}` exited {r.returncode}\n" + "\n".join(out)

def stop(ev, cfg, root):
    st = load_state(ev.get("session_id"))
    if not st["changed_files"]:
        return 0
    ok, out = run_tests(cfg, root)
    if ok:
        st["stop_retries"] = 0
        save_state(st)
        audit({"decision": "stop-ok", "evidence": out.splitlines()[0], "session": ev.get("session_id")})
        return 0
    st["stop_retries"] += 1
    save_state(st)
    if st["stop_retries"] > cfg["max_stop_retries"]:
        print(f"[agent-leash] tests still failing after {cfg['max_stop_retries']} tries; letting the agent stop. Do NOT trust its 'done'.\n{out}", file=sys.stderr)
        audit({"decision": "stop-gave-up", "session": ev.get("session_id")})
        return 0
    return block("evidence-required", "you changed code but the tests fail, so it is not done. Fix it or say plainly that it is broken (G8).\n" + out, ev)

def handle_hook():
    raw = sys.stdin.read()
    try:
        ev = json.loads(raw or "{}")
    except json.JSONDecodeError:
        print("[agent-leash] could not parse hook input; failing closed", file=sys.stderr)
        return 2
    cwd = ev.get("cwd") or os.getcwd()
    root = project_root(cwd)
    cfg = load_config(root)
    name = ev.get("hook_event_name", "PreToolUse")
    if name == "PreToolUse":
        return pre_tool(ev, cfg, root)
    if name in ("PostToolUse", "PostToolUseFailure"):
        return post_tool(ev, cfg, root)
    if name in ("Stop", "SubagentStop"):
        return stop(ev, cfg, root)
    return 0

# ---------------------------------------------------------------- CLI

def precommit():
    root = project_root(os.getcwd())
    cfg = load_config(root)
    diff = subprocess.run(["git", "diff", "--cached", "-U0", "--no-color"], cwd=root, capture_output=True, text=True).stdout
    names = subprocess.run(["git", "diff", "--cached", "--name-only"], cwd=root, capture_output=True, text=True).stdout.split()
    for n in names:
        if SECRET_PATH.search(n) and not SECRET_PATH_OK.search(n):
            print(f"[agent-leash] commit blocked: {n} is a secret file", file=sys.stderr)
            return 1
    added = "\n".join(l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
    for name, rx in SECRET_VALUE:
        if rx.search(added):
            print(f"[agent-leash] commit blocked: staged changes contain a literal {name}", file=sys.stderr)
            return 1
    ok, out = run_tests(cfg, root)
    if not ok:
        print("[agent-leash] commit blocked: tests fail\n" + out, file=sys.stderr)
        return 1
    print("[agent-leash] pre-commit OK: no secrets, " + out.splitlines()[0])
    return 0

HOOK_CMD = 'python3 "$HOME/.agent-leash/leash.py" hook'

def merge_hooks(settings, events):
    hooks = settings.setdefault("hooks", {})
    for event, matcher in events:
        lst = hooks.setdefault(event, [])
        if any(h.get("command") == HOOK_CMD for e in lst for h in e.get("hooks", [])):
            continue
        entry = {"hooks": [{"type": "command", "command": HOOK_CMD, "timeout": 600 if event == "Stop" else 30}]}
        if matcher:
            entry["matcher"] = matcher
        lst.append(entry)
    return settings

def install(args):
    import shutil
    os.makedirs(LEASH_HOME, exist_ok=True)
    me = os.path.realpath(__file__)
    dest = os.path.join(LEASH_HOME, "leash.py")
    if me != os.path.realpath(dest):
        shutil.copy2(me, dest)
    cfgp = os.path.join(LEASH_HOME, "config.json")
    if not os.path.exists(cfgp):
        with open(cfgp, "w") as f:
            json.dump({k: DEFAULTS[k] for k in ("protected_branches", "lease_minutes", "max_tool_calls", "max_tokens", "max_usd", "test_command", "allow_commands", "deny_commands")}, f, indent=2)
    pre = ("PreToolUse", "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|Glob|apply_patch")
    post = ("PostToolUse", "Bash|Write|Edit|MultiEdit|NotebookEdit|apply_patch")
    done = []
    if "--claude" in args or len(args) == 0:
        p = os.path.join(HOME, ".claude", "settings.json")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        s = merge_hooks(load_json(p, {}), [pre, post, ("PostToolUseFailure", post[1]), ("Stop", None)])
        with open(p, "w") as f:
            json.dump(s, f, indent=2)
        done.append(p)
    if "--codex" in args or len(args) == 0:
        p = os.path.join(os.environ.get("CODEX_HOME", os.path.join(HOME, ".codex")), "hooks.json")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        s = merge_hooks(load_json(p, {}), [pre, post, ("Stop", None)])
        with open(p, "w") as f:
            json.dump(s, f, indent=2)
        done.append(p + "  (run /hooks in Codex once to trust it)")
    if "--git" in args:
        proj = args[args.index("--project") + 1] if "--project" in args else os.getcwd()
        hp = os.path.join(project_root(proj), ".git", "hooks", "pre-commit")
        with open(hp, "w") as f:
            f.write('#!/bin/sh\nexec python3 "$HOME/.agent-leash/leash.py" precommit\n')
        os.chmod(hp, 0o755)
        done.append(hp)
    print("agent-leash installed:\n  " + "\n  ".join([dest, cfgp] + done))
    return 0

def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    c = argv[0]
    if c == "hook":
        return handle_hook()
    if c == "check":
        cmd = " ".join(argv[1:])
        root = project_root(os.getcwd())
        hit = check_command(cmd, os.getcwd(), root, load_config(root))
        print(f"BLOCK ({hit[0]}): {hit[1]}" if hit else "ALLOW")
        return 2 if hit else 0
    if c == "precommit":
        return precommit()
    if c == "status":
        st = load_state(argv[1] if len(argv) > 1 else "default")
        print(json.dumps(st, indent=1))
        return 0
    if c == "resolve" and len(argv) >= 3:
        found = False
        for fn in os.listdir(os.path.join(LEASH_HOME, "state")):
            p = os.path.join(LEASH_HOME, "state", fn)
            st = load_json(p, {})
            if argv[1] in st.get("intents", {}):
                st["intents"][argv[1]]["status"] = "done" if argv[2] == "done" else "failed"
                save_state(st)
                found = True
        print("resolved" if found else "intent not found")
        return 0 if found else 1
    if c == "install":
        return install(argv[1:])
    if c == "--version":
        print(VERSION)
        return 0
    print(__doc__)
    return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

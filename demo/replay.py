#!/usr/bin/env python3
"""Replay the launch-demo scenarios through the real leash.py hook.

Builds a throwaway git repo, sends each tool call the way Claude Code sends it
(hook JSON on stdin), and prints what the hook decides.
  python3 demo/replay.py          human-readable
  python3 demo/replay.py --json   machine-readable (used to render the video)
"""
import json, os, shutil, subprocess, sys, tempfile, time

LEASH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "leash.py")

def main():
    tmp = tempfile.mkdtemp(prefix="leash-demo-")
    repo, home = os.path.join(tmp, "shop-api"), os.path.join(tmp, "home")
    os.makedirs(repo); os.makedirs(home)
    g = lambda *a: subprocess.run(["git", *a], cwd=repo, capture_output=True, check=True)
    g("init", "-q", "-b", "main"); g("config", "user.email", "d@d"); g("config", "user.name", "d")
    with open(os.path.join(repo, "cart.py"), "w") as f:
        f.write("def total(items):\n    return sum(i['price'] * i['qty'] for i in items)\n")
    with open(os.path.join(repo, "test_cart.py"), "w") as f:
        f.write("from cart import total\nok = total([{'price': 5, 'qty': 2}]) == 10\n"
                "print('1 passed' if ok else 'FAILED test_total: expected 10, got ' + str(total([{'price': 5, 'qty': 2}])))\n"
                "raise SystemExit(0 if ok else 1)\n")
    g("add", "."); g("commit", "-qm", "init")
    with open(os.path.join(home, "config.json"), "w") as f:
        json.dump({"test_command": "python3 test_cart.py", "max_tool_calls": 400, "allow_outside_root": []}, f)
    sid = "demo-" + str(int(time.time()))

    def hook(event, tool=None, ti=None, **extra):
        ev = {"hook_event_name": event, "session_id": sid, "cwd": repo, **extra}
        if tool: ev["tool_name"] = tool
        if ti is not None: ev["tool_input"] = ti
        r = subprocess.run([sys.executable, LEASH, "hook"], input=json.dumps(ev), capture_output=True, text=True,
                           env=dict(os.environ, LEASH_HOME=home), cwd=repo)
        return r.returncode, r.stderr.strip()

    out = []
    def step(label, res, note=""):
        out.append({"call": label, "blocked": res[0] == 2, "message": res[1] or "allowed", "note": note})

    step("Bash(rm -rf ./build)", hook("PreToolUse", "Bash", {"command": "rm -rf ./build"}))
    step("Bash(rm -rf $BUILD_DIR/)", hook("PreToolUse", "Bash", {"command": "rm -rf $BUILD_DIR/"}))
    step("Read(.env)", hook("PreToolUse", "Read", {"file_path": os.path.join(repo, ".env")}))
    step("Bash(git push --force origin main)", hook("PreToolUse", "Bash", {"command": "git push --force origin main"}))
    step("Bash(vercel deploy --prod)", hook("PreToolUse", "Bash", {"command": "vercel deploy --prod"}), "timed out, no result")
    step("Bash(vercel deploy --prod)", hook("PreToolUse", "Bash", {"command": "vercel deploy --prod"}), "retry")
    with open(os.path.join(repo, "cart.py"), "w") as f:   # the agent's edit breaks the totals
        f.write("def total(items):\n    return sum(i['price'] for i in items)\n")
    hook("PostToolUse", "Edit", {"file_path": os.path.join(repo, "cart.py")})
    step('Stop("All done! Cart totals fixed.")', hook("Stop", stop_hook_active=False))
    st = os.path.join(home, "state", sid + ".json")
    with open(st) as f: s = json.load(f)
    s["tool_calls"] = 400
    with open(st, "w") as f: json.dump(s, f)
    step("Bash(npm test)", hook("PreToolUse", "Bash", {"command": "npm test"}), "call #401")
    shutil.rmtree(tmp, ignore_errors=True)

    if "--json" in sys.argv:
        print(json.dumps(out, indent=1))
    else:
        for o in out:
            print(("BLOCKED  " if o["blocked"] else "ALLOWED  ") + o["call"] + (f"   [{o['note']}]" if o["note"] else ""))
            print("   " + o["message"].replace("\n", "\n   "))

if __name__ == "__main__":
    main()

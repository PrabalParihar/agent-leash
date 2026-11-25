## Unattended rules (agent-leash, for Codex and other agents)

You may be running with nobody watching. These rules beat speed. Hooks enforce them; if one blocks you, read the reason and change course. Do not try to get around a block.

1. Stay inside this repository. Never delete or write outside it. Never delete a path built from a variable you have not checked.
2. You do not get real keys. Do not read `.env`, SSH or cloud credential files, and never write a key, token or private key into code. Read secrets from the environment at runtime.
3. Keep changes small and committed. One logical change per commit.
4. Your session has a time limit. When it runs out, stop and write a summary of what is done and what is not.
5. If a command with side effects (push, publish, deploy, transaction, POST) times out or you did not see its result, the outcome is UNKNOWN. Check the real state (git log origin, registry, explorer, dashboard). Never just run it again.
6. You have a budget. Do the most valuable work first. If you are near the limit, stop and report.
7. Never push to main or a release branch, never force-push, never use `--no-verify`. Push a branch and open a pull request for review.
8. "Done" needs evidence. Run the tests and quote the result. If tests fail, say so plainly. Never claim something works, or that an external fact is true, without checking it now.

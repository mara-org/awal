# Awal

Your README is a promise.

Most repos break that promise quietly.

A new developer clones the project, follows the first command, then loses twenty minutes because the
script name changed, the env file is stale, the Docker command never had a compose file, or the port
in the docs is from three refactors ago.

Awal checks that first-run path before someone else pays for it.

No command execution.
No network calls.
No cloud upload.
No LLM.

Just a local README truth check for developer onboarding.

## What It Checks

Awal scans the README and compares it with the repo surface:

- README commands that call missing `package.json` scripts.
- `npm`, `pnpm`, `yarn`, or `bun` drift against the lockfile.
- `npm test` pointing to the default fake test script.
- Docker Compose commands with no compose file.
- Docker build commands with no Dockerfile.
- Python install commands with no `pyproject.toml`, `setup.py`, or `requirements.txt`.
- README `.env` instructions with no `.env.example`.
- env vars used in code but missing from `.env.example`.
- secret-looking values committed inside example env files.
- README URLs whose port disagrees with the dev script.
- README commands that `cd` into folders that do not exist.
- risky bootstrap commands like `curl | bash`, `chmod 777`, or destructive `rm`.

It answers one question:

Can a fresh developer trust the README?

## Install

For now:

```bash
python3 -m pip install -e .
```

Later, if the package earns it:

```bash
pip install awal
```

## Quick Start

```bash
awal .
awal scan ./some-repo
awal examples/broken-app
```

Run without installing:

```bash
PYTHONPATH=src python3 -m awal examples/broken-app
```

## UI

```bash
awal ui
```

Open:

```text
http://127.0.0.1:8774/
```

Type a local repo path and scan it.

## Example Output

```text
AWAL BLOCK: 6 issue(s)
Target: examples/broken-app
Risk score: 84
Summary: critical=0 high=4 medium=2 low=0

HIGH  missing_package_script  README.md:7
npm run serve
Why: The README tells a fresh developer to run a package script that does not exist.
Fix: Add `serve` to package.json scripts or fix the README command.
```

## Output Formats

```bash
awal . --format text
awal . --format json --output awal-report.json
awal . --format csv --output awal-report.csv
awal . --format sarif --output awal.sarif
```

## Release Gates

```bash
awal . --fail-on high
awal . --fail-on medium
```

Exit codes:

- `0`: pass
- `1`: review findings found
- `2`: blocked by `--fail-on`

## Scope

Awal does not run your README commands.

That is intentional for v1.

It statically checks whether the commands, files, env keys, package scripts, and ports mentioned in
the README match what exists in the repo.

## Development

```bash
python3 -m unittest discover -s tests
python3 -m compileall src tests
python3 -m pip wheel . -w /tmp/awal-wheel
```

## Roadmap

- Optional safe dry-run mode in a temporary folder.
- GitHub Action for README drift on pull requests.
- More framework port detection.
- Monorepo workspace detection.
- Markdown report export.

## Contributing

PRs are welcome if they make first-run developer onboarding harder to fake.

Regards,
The CTO.

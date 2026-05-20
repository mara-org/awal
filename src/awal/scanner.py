from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .models import SEVERITY_RANK, SEVERITY_WEIGHT, Finding, ScanReport


README_NAMES = ("README.md", "README.markdown", "README.txt", "README")
COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
ENV_EXAMPLE_NAMES = (".env.example", ".env.sample", "env.example", "env.sample")
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "__pycache__",
}
TEXT_SUFFIXES = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".py",
    ".rb",
    ".go",
    ".php",
    ".java",
    ".kt",
    ".rs",
    ".sh",
    ".yml",
    ".yaml",
    ".toml",
    ".json",
}
COMMON_ENV_KEYS = {
    "CI",
    "HOME",
    "LANG",
    "NODE_ENV",
    "PATH",
    "PORT",
    "PWD",
    "PYTHONPATH",
    "SHELL",
    "TERM",
    "USER",
}

FENCED_BLOCK_PATTERN = re.compile(r"```(?:bash|sh|shell|zsh|console|terminal|text)?\s*\n(?P<body>.*?)```", re.I | re.S)
INLINE_COMMAND_PATTERN = re.compile(
    r"`(?P<cmd>(?:npm|pnpm|yarn|bun|python3?|pip3?|uv|poetry|docker|make|cargo|go|php|composer)\s+[^`]+)`"
)
URL_PORT_PATTERN = re.compile(r"\b(?:localhost|127\.0\.0\.1):(?P<port>\d{2,5})\b")
ENV_REFERENCE_PATTERN = re.compile(r"\.env(?:\.example|\.sample)?\b|\benvironment variables?\b|\bAPI_KEY\b|\bDATABASE_URL\b", re.I)
DANGEROUS_COMMAND_PATTERN = re.compile(
    r"\bcurl\b[^\n|;&]+[|]\s*(?:bash|sh)\b|\bwget\b[^\n|;&]+[|]\s*(?:bash|sh)\b|\bsudo\s+rm\s+-rf\b|\brm\s+-rf\s+/(?:\s|$)|\bchmod\s+777\b",
    re.I,
)
ENV_USAGE_PATTERNS = (
    re.compile(r"\bprocess\.env\.([A-Z][A-Z0-9_]{2,})"),
    re.compile(r"\bprocess\.env\[['\"]([A-Z][A-Z0-9_]{2,})['\"]\]"),
    re.compile(r"\bimport\.meta\.env\.([A-Z][A-Z0-9_]{2,})"),
    re.compile(r"\bDeno\.env\.get\(['\"]([A-Z][A-Z0-9_]{2,})['\"]\)"),
    re.compile(r"\bos\.environ(?:\.get)?\(['\"]([A-Z][A-Z0-9_]{2,})['\"]\)"),
    re.compile(r"\bos\.getenv\(['\"]([A-Z][A-Z0-9_]{2,})['\"]\)"),
    re.compile(r"\bENV\[['\"]([A-Z][A-Z0-9_]{2,})['\"]\]"),
)
SECRET_KEY_PATTERN = re.compile(r"(SECRET|TOKEN|PASSWORD|PRIVATE|API[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET)", re.I)
SAFE_VALUE_PATTERN = re.compile(r"^(|change.?me|example|placeholder|dummy|test|todo|your_.+|<.+>|\$\{.+\}|localhost|127\.0\.0\.1|null|none)$", re.I)


@dataclass(frozen=True)
class ReadmeCommand:
    text: str
    line: int


@dataclass(frozen=True)
class RepoSurface:
    root: Path
    readme_path: Path | None
    readme_text: str
    commands: tuple[ReadmeCommand, ...]
    package_scripts: dict[str, str]
    package_manager: str | None
    has_pyproject: bool
    has_setup_py: bool
    has_requirements: bool
    has_dockerfile: bool
    has_compose: bool
    env_example_paths: tuple[Path, ...]
    env_example_keys: dict[str, str]
    env_usages: dict[str, tuple[str, int]]


def scan_path(path: str | Path, *, fail_on: str = "high") -> ScanReport:
    root = Path(path).expanduser().resolve()
    findings: list[Finding] = []
    if not root.exists():
        findings.append(
            Finding(
                file=str(root),
                line=1,
                severity="critical",
                category="missing_path",
                excerpt=str(root),
                why_it_matters="Awal cannot check a repo that does not exist.",
                suggested_review="Pass a valid local repository path.",
                rule_id="missing_path",
            )
        )
        return build_report(root, findings, None, fail_on)

    surface = inspect_repo(root)
    if surface.readme_path is None:
        findings.append(
            Finding(
                file=str(root),
                line=1,
                severity="high",
                category="missing_readme",
                excerpt="No README found",
                why_it_matters="A fresh developer has no canonical first-run path.",
                suggested_review="Add a README with install, environment, and run commands.",
                rule_id="missing_readme",
            )
        )
        return build_report(root, findings, surface, fail_on)

    findings.extend(command_findings(surface))
    findings.extend(package_manager_findings(surface))
    findings.extend(env_findings(surface))
    findings.extend(docker_findings(surface))
    findings.extend(port_findings(surface))
    findings.extend(readme_shape_findings(surface))
    return build_report(root, findings, surface, fail_on)


def inspect_repo(root: Path) -> RepoSurface:
    readme_path = first_existing(root, README_NAMES)
    readme_text = read_text(readme_path) if readme_path else ""
    package_scripts = load_package_scripts(root / "package.json")
    env_paths = tuple(find_named_files(root, ENV_EXAMPLE_NAMES, max_depth=4))
    return RepoSurface(
        root=root,
        readme_path=readme_path,
        readme_text=readme_text,
        commands=tuple(extract_commands(readme_text)),
        package_scripts=package_scripts,
        package_manager=detect_package_manager(root),
        has_pyproject=(root / "pyproject.toml").exists(),
        has_setup_py=(root / "setup.py").exists(),
        has_requirements=(root / "requirements.txt").exists(),
        has_dockerfile=(root / "Dockerfile").exists(),
        has_compose=any((root / name).exists() for name in COMPOSE_NAMES),
        env_example_paths=env_paths,
        env_example_keys=parse_env_examples(env_paths),
        env_usages=find_env_usages(root),
    )


def command_findings(surface: RepoSurface) -> list[Finding]:
    findings: list[Finding] = []
    for command in surface.commands:
        text = normalize_command(command.text)
        if not text:
            continue
        if DANGEROUS_COMMAND_PATTERN.search(text):
            findings.append(
                Finding(
                    file=readme_file(surface),
                    line=command.line,
                    severity="critical",
                    category="dangerous_bootstrap",
                    excerpt=clip(text),
                    why_it_matters="The README asks new developers to run a risky bootstrap command.",
                    suggested_review="Replace it with a pinned, reviewable install step.",
                    rule_id="dangerous_bootstrap",
                )
            )
        findings.extend(cd_findings(surface, text, command.line))
        script = package_script_from_command(text)
        if script is not None and surface.package_scripts:
            script_name, display = script
            if script_name not in surface.package_scripts:
                findings.append(
                    Finding(
                        file=readme_file(surface),
                        line=command.line,
                        severity="high",
                        category="missing_package_script",
                        excerpt=display,
                        why_it_matters="The README tells a fresh developer to run a package script that does not exist.",
                        suggested_review=f"Add `{script_name}` to package.json scripts or fix the README command.",
                        rule_id="missing_package_script",
                    )
                )
            elif script_name == "test" and is_placeholder_test(surface.package_scripts[script_name]):
                findings.append(
                    Finding(
                        file="package.json",
                        line=1,
                        severity="high",
                        category="placeholder_test_script",
                        excerpt=surface.package_scripts[script_name],
                        why_it_matters="The README promises tests, but package.json still has the default failing placeholder.",
                        suggested_review="Replace the placeholder with a real test command or remove the README promise.",
                        rule_id="placeholder_test_script",
                    )
                )
        findings.extend(python_command_findings(surface, text, command.line))
    return findings


def package_manager_findings(surface: RepoSurface) -> list[Finding]:
    if not surface.package_manager:
        return []
    findings: list[Finding] = []
    for command in surface.commands:
        manager = command_package_manager(command.text)
        if manager and manager != surface.package_manager:
            findings.append(
                Finding(
                    file=readme_file(surface),
                    line=command.line,
                    severity="medium",
                    category="package_manager_drift",
                    excerpt=clip(command.text),
                    why_it_matters=f"The repo lockfile points to `{surface.package_manager}`, but the README uses `{manager}`.",
                    suggested_review=f"Use `{surface.package_manager}` in the README or commit the matching lockfile.",
                    rule_id="package_manager_drift",
                )
            )
    return findings


def env_findings(surface: RepoSurface) -> list[Finding]:
    findings: list[Finding] = []
    readme_mentions_env = bool(ENV_REFERENCE_PATTERN.search(surface.readme_text))
    if (surface.env_usages or readme_mentions_env) and not surface.env_example_paths:
        findings.append(
            Finding(
                file=readme_file(surface),
                line=line_for_pattern(surface.readme_text, ENV_REFERENCE_PATTERN),
                severity="high",
                category="missing_env_example",
                excerpt=".env.example not found",
                why_it_matters="The repo depends on environment values, but a fresh developer has no safe template.",
                suggested_review="Add `.env.example` with required keys and safe placeholder values.",
                rule_id="missing_env_example",
            )
        )
    if surface.env_example_paths:
        for key, (file_name, line) in surface.env_usages.items():
            if key not in surface.env_example_keys:
                findings.append(
                    Finding(
                        file=file_name,
                        line=line,
                        severity="high",
                        category="undocumented_env_var",
                        excerpt=key,
                        why_it_matters="The code reads an environment variable that is missing from the example env file.",
                        suggested_review=f"Add `{key}=` to the env example with a safe placeholder and a short comment.",
                        rule_id="undocumented_env_var",
                    )
                )
        for key, value in surface.env_example_keys.items():
            if SECRET_KEY_PATTERN.search(key) and value and not SAFE_VALUE_PATTERN.match(value.strip()):
                findings.append(
                    Finding(
                        file=env_file_for_key(surface, key),
                        line=1,
                        severity="critical",
                        category="env_example_secret",
                        excerpt=f"{key}={clip(value)}",
                        why_it_matters="An example env file appears to contain a real secret-shaped value.",
                        suggested_review="Remove the value, rotate it if real, and replace it with a placeholder.",
                        rule_id="env_example_secret",
                    )
                )
    return findings


def docker_findings(surface: RepoSurface) -> list[Finding]:
    findings: list[Finding] = []
    for command in surface.commands:
        text = normalize_command(command.text)
        if re.search(r"\bdocker\s+compose\s+up\b|\bdocker-compose\s+up\b", text) and not surface.has_compose:
            findings.append(
                Finding(
                    file=readme_file(surface),
                    line=command.line,
                    severity="high",
                    category="missing_compose_file",
                    excerpt=clip(text),
                    why_it_matters="The README promises Docker Compose, but no compose file exists at the repo root.",
                    suggested_review="Add a compose file or update the README with the actual run path.",
                    rule_id="missing_compose_file",
                )
            )
        if re.search(r"\bdocker\s+build\b", text) and not surface.has_dockerfile:
            findings.append(
                Finding(
                    file=readme_file(surface),
                    line=command.line,
                    severity="high",
                    category="missing_dockerfile",
                    excerpt=clip(text),
                    why_it_matters="The README promises a Docker build, but no Dockerfile exists at the repo root.",
                    suggested_review="Add a Dockerfile or fix the command path.",
                    rule_id="missing_dockerfile",
                )
            )
    return findings


def port_findings(surface: RepoSurface) -> list[Finding]:
    readme_ports = set(URL_PORT_PATTERN.findall(surface.readme_text))
    script_ports = ports_from_scripts(surface.package_scripts)
    if len(readme_ports) != 1 or len(script_ports) != 1:
        return []
    readme_port = next(iter(readme_ports))
    script_port = next(iter(script_ports))
    if readme_port == script_port:
        return []
    return [
        Finding(
            file=readme_file(surface),
            line=line_for_pattern(surface.readme_text, URL_PORT_PATTERN),
            severity="medium",
            category="port_drift",
            excerpt=f"README says localhost:{readme_port}, scripts suggest {script_port}",
            why_it_matters="Fresh developers follow the README URL. A stale port looks like a broken app.",
            suggested_review="Update the README URL or the dev script port so they match.",
            rule_id="port_drift",
        )
    ]


def readme_shape_findings(surface: RepoSurface) -> list[Finding]:
    if surface.commands:
        return []
    return [
        Finding(
            file=readme_file(surface),
            line=1,
            severity="medium",
            category="missing_quickstart",
            excerpt="No install/run commands found",
            why_it_matters="The README does not give a fresh developer a copy-pasteable first-run path.",
            suggested_review="Add a short Quick Start with install, env setup, and run commands.",
            rule_id="missing_quickstart",
        )
    ]


def build_report(root: Path, findings: list[Finding], surface: RepoSurface | None, fail_on: str) -> ScanReport:
    findings.sort(key=lambda item: (-SEVERITY_RANK[item.severity], item.file, item.line, item.rule_id))
    threshold = SEVERITY_RANK[fail_on]
    status = "pass"
    if findings:
        status = "block" if any(SEVERITY_RANK[finding.severity] >= threshold for finding in findings) else "review"
    summary = build_summary(findings)
    summary["repo"] = {
        "readme": str(surface.readme_path.name) if surface and surface.readme_path else None,
        "commands": len(surface.commands) if surface else 0,
        "package_manager": surface.package_manager if surface else None,
        "package_scripts": sorted(surface.package_scripts) if surface else [],
        "env_usages": sorted(surface.env_usages) if surface else [],
        "env_example_keys": sorted(surface.env_example_keys) if surface else [],
    }
    return ScanReport(
        status=status,
        risk_score=calculate_risk_score(findings),
        target=str(root),
        summary=summary,
        findings=tuple(findings),
    )


def build_summary(findings: list[Finding]) -> dict[str, object]:
    by_severity = {severity: 0 for severity in SEVERITY_RANK}
    by_category: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] += 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": dict(sorted(by_category.items())),
    }


def calculate_risk_score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_WEIGHT[finding.severity] for finding in findings))


def first_existing(root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        path = root / name
        if path.exists() and path.is_file():
            return path
    return None


def read_text(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def extract_commands(readme_text: str) -> list[ReadmeCommand]:
    commands: list[ReadmeCommand] = []
    for block in FENCED_BLOCK_PATTERN.finditer(readme_text):
        start_line = readme_text.count("\n", 0, block.start("body")) + 1
        for offset, line in enumerate(block.group("body").splitlines()):
            command = clean_command_line(line)
            if is_command_like(command):
                commands.append(ReadmeCommand(text=command, line=start_line + offset))
    for match in INLINE_COMMAND_PATTERN.finditer(readme_text):
        command = clean_command_line(match.group("cmd"))
        if is_command_like(command):
            commands.append(ReadmeCommand(text=command, line=readme_text.count("\n", 0, match.start()) + 1))
    return dedupe_commands(commands)


def clean_command_line(line: str) -> str:
    stripped = line.strip()
    stripped = re.sub(r"^\$+\s*", "", stripped)
    stripped = re.sub(r"^>\s*", "", stripped)
    if stripped.startswith("#"):
        return ""
    return stripped.strip()


def is_command_like(command: str) -> bool:
    return bool(
        command
        and not command.startswith(("{", "}", "[", "]"))
        and re.match(r"^(cd|cp|npm|pnpm|yarn|bun|python3?|pip3?|uv|poetry|docker|make|cargo|go|php|composer|export)\b", command)
    )


def dedupe_commands(commands: list[ReadmeCommand]) -> list[ReadmeCommand]:
    seen: set[tuple[str, int]] = set()
    unique: list[ReadmeCommand] = []
    for command in commands:
        key = (command.text, command.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(command)
    return unique


def load_package_scripts(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return {}
    return {str(key): str(value) for key, value in scripts.items()}


def detect_package_manager(root: Path) -> str | None:
    if (root / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (root / "yarn.lock").exists():
        return "yarn"
    if (root / "bun.lockb").exists() or (root / "bun.lock").exists():
        return "bun"
    if (root / "package-lock.json").exists():
        return "npm"
    return None


def package_script_from_command(command: str) -> tuple[str, str] | None:
    match = re.search(r"\b(?:npm|pnpm|bun)\s+run\s+([A-Za-z0-9:_-]+)\b", command)
    if match:
        return match.group(1), match.group(0)
    match = re.search(r"\byarn\s+([A-Za-z0-9:_-]+)\b", command)
    if match and match.group(1) not in {"add", "install", "global", "dlx"}:
        return match.group(1), match.group(0)
    if re.search(r"\bnpm\s+start\b", command):
        return "start", "npm start"
    if re.search(r"\bnpm\s+test\b", command):
        return "test", "npm test"
    return None


def command_package_manager(command: str) -> str | None:
    match = re.match(r"\s*(npm|pnpm|yarn|bun)\b", command)
    return match.group(1) if match else None


def is_placeholder_test(script: str) -> bool:
    return bool(re.search(r"no test specified|exit 1|todo|placeholder", script, re.I))


def python_command_findings(surface: RepoSurface, command: str, line: int) -> list[Finding]:
    findings: list[Finding] = []
    if re.search(r"\b(?:python3?\s+-m\s+pip|pip3?)\s+install\s+-e\s+\.", command):
        if not (surface.has_pyproject or surface.has_setup_py):
            findings.append(
                Finding(
                    file=readme_file(surface),
                    line=line,
                    severity="high",
                    category="missing_python_project",
                    excerpt=clip(command),
                    why_it_matters="The README promises editable Python install, but no pyproject.toml or setup.py exists.",
                    suggested_review="Add Python package metadata or fix the install command.",
                    rule_id="missing_python_project",
                )
            )
    if re.search(r"\b(?:python3?\s+-m\s+pip|pip3?)\s+install\s+-r\s+requirements\.txt\b", command):
        if not surface.has_requirements:
            findings.append(
                Finding(
                    file=readme_file(surface),
                    line=line,
                    severity="high",
                    category="missing_requirements_file",
                    excerpt=clip(command),
                    why_it_matters="The README references requirements.txt, but the file does not exist.",
                    suggested_review="Add requirements.txt or update the install command.",
                    rule_id="missing_requirements_file",
                )
            )
    if re.search(r"\buv\s+sync\b|\bpoetry\s+install\b", command) and not surface.has_pyproject:
        findings.append(
            Finding(
                file=readme_file(surface),
                line=line,
                severity="high",
                category="missing_pyproject",
                excerpt=clip(command),
                why_it_matters="The README uses a Python project manager, but pyproject.toml is missing.",
                suggested_review="Add pyproject.toml or fix the setup instructions.",
                rule_id="missing_pyproject",
            )
        )
    return findings


def cd_findings(surface: RepoSurface, command: str, line: int) -> list[Finding]:
    findings: list[Finding] = []
    for match in re.finditer(r"(?:^|&&|\b)\s*cd\s+([A-Za-z0-9_./-]+)", command):
        raw = match.group(1).rstrip("/")
        if raw in {".", ".."}:
            continue
        target = (surface.root / raw).resolve()
        try:
            target.relative_to(surface.root)
        except ValueError:
            continue
        if not target.exists() or not target.is_dir():
            findings.append(
                Finding(
                    file=readme_file(surface),
                    line=line,
                    severity="high",
                    category="missing_command_directory",
                    excerpt=f"cd {raw}",
                    why_it_matters="The README asks a fresh developer to enter a directory that does not exist.",
                    suggested_review="Create the directory or correct the command path.",
                    rule_id="missing_command_directory",
                )
            )
    return findings


def find_named_files(root: Path, names: tuple[str, ...], *, max_depth: int) -> list[Path]:
    matches: list[Path] = []
    for path in root.rglob("*"):
        if should_ignore(path, root):
            continue
        try:
            depth = len(path.relative_to(root).parts)
        except ValueError:
            continue
        if depth > max_depth:
            continue
        if path.is_file() and path.name in names:
            matches.append(path)
    return sorted(matches)


def should_ignore(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in IGNORED_DIRS for part in parts)


def parse_env_examples(paths: tuple[Path, ...]) -> dict[str, str]:
    keys: dict[str, str] = {}
    for path in paths:
        for line in read_text(path).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            if re.match(r"^[A-Z][A-Z0-9_]{2,}$", key):
                keys[key] = value.strip().strip("'\"")
    return keys


def find_env_usages(root: Path) -> dict[str, tuple[str, int]]:
    usages: dict[str, tuple[str, int]] = {}
    for path in root.rglob("*"):
        if should_ignore(path, root) or not path.is_file() or path.suffix not in TEXT_SUFFIXES:
            continue
        if path.stat().st_size > 400_000:
            continue
        text = read_text(path)
        relative = str(path.relative_to(root))
        for line_number, line in enumerate(text.splitlines(), start=1):
            for pattern in ENV_USAGE_PATTERNS:
                for match in pattern.finditer(line):
                    key = match.group(1)
                    if key in COMMON_ENV_KEYS:
                        continue
                    usages.setdefault(key, (relative, line_number))
    return usages


def env_file_for_key(surface: RepoSurface, key: str) -> str:
    for path in surface.env_example_paths:
        for line in read_text(path).splitlines():
            if line.strip().startswith(f"{key}="):
                return str(path.relative_to(surface.root))
    return str(surface.env_example_paths[0].relative_to(surface.root)) if surface.env_example_paths else ".env.example"


def ports_from_scripts(scripts: dict[str, str]) -> set[str]:
    ports: set[str] = set()
    for script in scripts.values():
        for match in re.finditer(r"(?:--port\s+|PORT=)(\d{2,5})\b", script):
            ports.add(match.group(1))
    return ports


def normalize_command(command: str) -> str:
    return " ".join(command.split())


def line_for_pattern(text: str, pattern: re.Pattern[str]) -> int:
    match = pattern.search(text)
    if not match:
        return 1
    return text.count("\n", 0, match.start()) + 1


def readme_file(surface: RepoSurface) -> str:
    return surface.readme_path.name if surface.readme_path else "README"


def clip(value: str, limit: int = 180) -> str:
    value = " ".join(value.split())
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."

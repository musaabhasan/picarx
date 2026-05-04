from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    status: str
    severity: str
    evidence: str
    recommendation: str


def run_checks(root: Path) -> list[Finding]:
    root = root.resolve()
    return [
        check_os_release(root),
        check_default_hostname(root),
        check_default_pi_user(root),
        check_ssh_password_auth(root),
        check_ssh_root_login(root),
        check_firewall_tooling(root),
        check_sudo_nopasswd(root),
    ]


def check_os_release(root: Path) -> Finding:
    values = parse_key_value_file(root / "etc" / "os-release")
    pretty = values.get("PRETTY_NAME") or values.get("NAME")
    if pretty:
        return Finding(
            "OS-001",
            "Operating system metadata found",
            "pass",
            "info",
            pretty,
            "Keep the base image documented for each lab cohort.",
        )
    return Finding(
        "OS-001",
        "Operating system metadata missing",
        "manual",
        "low",
        "No /etc/os-release file found under the target root.",
        "Confirm the target root path and record the base image manually.",
    )


def check_default_hostname(root: Path) -> Finding:
    hostname = read_text(root / "etc" / "hostname").strip()
    if not hostname:
        return Finding(
            "ID-001",
            "Hostname not found",
            "manual",
            "low",
            "No /etc/hostname file found under the target root.",
            "Assign and document a unique hostname for each lab device.",
        )
    if hostname.lower() == "raspberrypi":
        return Finding(
            "ID-001",
            "Default hostname detected",
            "fail",
            "low",
            "Hostname is raspberrypi.",
            "Use a unique hostname that maps to the lab asset inventory.",
        )
    return Finding(
        "ID-001",
        "Hostname is customized",
        "pass",
        "info",
        f"Hostname is {hostname}.",
        "Keep hostname naming consistent with the lab inventory.",
    )


def check_default_pi_user(root: Path) -> Finding:
    users = parse_passwd_users(root / "etc" / "passwd")
    if "pi" in users:
        return Finding(
            "AC-001",
            "Default pi user exists",
            "warn",
            "medium",
            "User pi is present in /etc/passwd.",
            "Confirm the account is needed, has a strong password, and is documented.",
        )
    if users:
        return Finding(
            "AC-001",
            "Default pi user not found",
            "pass",
            "info",
            "No pi user was found in /etc/passwd.",
            "Continue using named accounts or documented lab accounts.",
        )
    return Finding(
        "AC-001",
        "User database not found",
        "manual",
        "low",
        "No /etc/passwd file found under the target root.",
        "Confirm account posture manually.",
    )


def check_ssh_password_auth(root: Path) -> Finding:
    values = parse_sshd_config(root / "etc" / "ssh" / "sshd_config")
    value = values.get("passwordauthentication")
    if value == "no":
        return Finding(
            "SSH-001",
            "SSH password authentication disabled",
            "pass",
            "info",
            "PasswordAuthentication no",
            "Continue using managed SSH keys for administration.",
        )
    if value == "yes":
        return Finding(
            "SSH-001",
            "SSH password authentication enabled",
            "fail",
            "high",
            "PasswordAuthentication yes",
            "Disable password authentication where feasible and use SSH keys.",
        )
    return Finding(
        "SSH-001",
        "SSH password authentication not explicit",
        "manual",
        "medium",
        "PasswordAuthentication was not found in sshd_config.",
        "Set PasswordAuthentication explicitly according to lab policy.",
    )


def check_ssh_root_login(root: Path) -> Finding:
    values = parse_sshd_config(root / "etc" / "ssh" / "sshd_config")
    value = values.get("permitrootlogin")
    if value == "no":
        return Finding(
            "SSH-002",
            "SSH root login disabled",
            "pass",
            "info",
            "PermitRootLogin no",
            "Keep direct root login disabled.",
        )
    if value in {"yes", "without-password", "prohibit-password"}:
        return Finding(
            "SSH-002",
            "SSH root login is not fully disabled",
            "warn",
            "high",
            f"PermitRootLogin {value}",
            "Disable direct root login and use named administrative accounts.",
        )
    return Finding(
        "SSH-002",
        "SSH root login not explicit",
        "manual",
        "medium",
        "PermitRootLogin was not found in sshd_config.",
        "Set PermitRootLogin no unless a documented exception exists.",
    )


def check_firewall_tooling(root: Path) -> Finding:
    candidates = [
        root / "usr" / "sbin" / "ufw",
        root / "usr" / "bin" / "firewall-cmd",
        root / "sbin" / "iptables",
        root / "usr" / "sbin" / "nft",
    ]
    found = [path.relative_to(root).as_posix() for path in candidates if path.exists()]
    if found:
        return Finding(
            "NET-001",
            "Firewall tooling indicator found",
            "manual",
            "medium",
            ", ".join(found),
            "Confirm firewall rules or equivalent network segmentation are active.",
        )
    return Finding(
        "NET-001",
        "No firewall tooling indicator found",
        "warn",
        "medium",
        "No common firewall command paths were found.",
        "Confirm host firewall tooling or network-level segmentation.",
    )


def check_sudo_nopasswd(root: Path) -> Finding:
    sudo_paths = [root / "etc" / "sudoers"]
    sudo_dir = root / "etc" / "sudoers.d"
    if sudo_dir.is_dir():
        sudo_paths.extend(path for path in sudo_dir.iterdir() if path.is_file())

    matches = []
    for path in sudo_paths:
        text = read_text(path)
        if text:
            matches.extend(find_nopasswd_lines(text, path.relative_to(root).as_posix()))

    if matches:
        return Finding(
            "AC-002",
            "Passwordless sudo entries found",
            "warn",
            "medium",
            "; ".join(matches),
            "Review whether NOPASSWD is needed for the lab and document exceptions.",
        )
    if any(path.exists() for path in sudo_paths):
        return Finding(
            "AC-002",
            "No passwordless sudo entries found",
            "pass",
            "info",
            "No NOPASSWD entries found in sudoers files inspected.",
            "Keep administrative privileges limited and documented.",
        )
    return Finding(
        "AC-002",
        "Sudoers files not found",
        "manual",
        "low",
        "No sudoers files found under the target root.",
        "Confirm privilege escalation paths manually.",
    )


def parse_key_value_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in read_text(path).splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')
    return values


def parse_sshd_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            values[parts[0].lower()] = parts[1].strip().lower()
    return values


def parse_passwd_users(path: Path) -> set[str]:
    users: set[str] = set()
    for line in read_text(path).splitlines():
        if not line or line.startswith("#") or ":" not in line:
            continue
        users.add(line.split(":", 1)[0])
    return users


def find_nopasswd_lines(text: str, source: str) -> Iterable[str]:
    for index, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "NOPASSWD" in line.upper():
            yield f"{source}:{index}"


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

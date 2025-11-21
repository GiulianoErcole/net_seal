#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import subprocess
import time
from pathlib import Path
from typing import Iterable, List, Set, Tuple

# Command to list TCP/UDP sockets (numeric, all)
SS_CMD: List[str] = ["ss", "-tuna"]

# Regex to match lines like:
# ESTAB 0 0 192.168.1.50:43210 142.250.191.142:443
LINE_RX = re.compile(
    r"^\S+\s+\S+\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)",
)


def snap_connections() -> List[Tuple[str, str, str, str]]:
    """Return a snapshot of TCP/UDP connections.

    Returns:
        List of tuples in the form:
        (local_ip, local_port, remote_ip, remote_port)
    """
    try:
        out = subprocess.check_output(
            SS_CMD,
            text=True,
            stderr=subprocess.DEVNULL,  # type: ignore[attr-defined]
        )
    except Exception:
        # If ss is not available or errors, just return an empty list.
        return []

    connections: List[Tuple[str, str, str, str]] = []

    for line in out.splitlines():
        match = LINE_RX.search(line.strip())
        if not match:
            continue

        lip, lport, rip, rport = match.groups()

        # Ignore weird 0.0.0.0 remotes
        if rip.startswith("0.") or rip == "0.0.0.0":
            continue

        # Ignore localhost remotes; loopback is already allowed
        if rip.startswith("127."):
            continue

        connections.append((lip, lport, rip, rport))

    return connections


def observe(seconds: int, poll_interval: float = 0.5) -> Set[Tuple[str, str]]:
    """Watch connections for `seconds` and return unique (remote_ip, remote_port) pairs.

    Args:
        seconds: Total number of seconds to observe connections.
        poll_interval: Delay between polls in seconds.

    Returns:
        A set of (remote_ip, remote_port) tuples.
    """
    seen: Set[Tuple[str, str]] = set()
    start_time = time.time()

    while time.time() - start_time < seconds:
        for _lip, _lport, rip, rport in snap_connections():
            seen.add((rip, rport))
        time.sleep(poll_interval)

    return seen


def _iptables_header_lines() -> List[str]:
    """Return the standard iptables header/setup lines."""
    lines: List[str] = [
        "#!/bin/sh",
        "# WARNING: This will aggressively lock down outbound traffic.",
        "# Review before running. Run with sudo.",
        "",
        "iptables -F",
        "iptables -X",
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        # We'll default OUTPUT to DROP at the end, after we add allow rules.
        "iptables -P OUTPUT ACCEPT",
        "",
        "# allow loopback",
        "iptables -A INPUT -i lo -j ACCEPT",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "",
        "# allow established/related",
        "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "",
        "# allow DNS (udp/tcp 53) outbound (automatically included by default)",
        "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
        "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT",
        "",
        "# allow captured outbound destinations",
    ]
    return lines


def generate_iptables_script(
    allowed: Iterable[Tuple[str, str]],
    out_path: Path,
    default_drop: bool = True,
) -> None:
    """Write a .sh script that enforces the observed outbound allowlist.

    The generated script will:
        - Flush iptables.
        - Allow loopback.
        - Allow ESTABLISHED,RELATED.
        - Allow DNS (53/tcp & 53/udp).
        - Allow outbound to provided IP:port pairs.
        - Optionally set OUTPUT policy to DROP for everything else.

    Args:
        allowed: Iterable of (remote_ip, remote_port) tuples.
        out_path: Path to write the lockdown script to.
        default_drop: If True, set OUTPUT policy to DROP at the end.
    """
    lines = _iptables_header_lines()

    for rip, rport in sorted(set(allowed)):
        # Use || true so script continues even if a rule fails.
        lines.append(f"iptables -A OUTPUT -p tcp -d {rip} --dport {rport} -j ACCEPT || true")
        lines.append(f"iptables -A OUTPUT -p udp -d {rip} --dport {rport} -j ACCEPT || true")

    lines.append("")
    if default_drop:
        lines.append("# default: drop EVERYTHING else outbound")
        lines.append("iptables -P OUTPUT DROP")
    lines.append("")

    out_path.write_text("\n".join(lines))
    out_path.chmod(0o700)


def pretty_preview(allowed: Set[Tuple[str, str]]) -> None:
    """Print a human-readable preview of the observed destinations."""
    if not allowed:
        print(
            "\n[!] No outbound connections observed. Your seal script will block "
            "basically everything.",
        )
        return

    print("\nObserved outbound destinations (IP:port):")
    for rip, rport in sorted(allowed):
        print(f"  {rip}:{rport}")

    print(f"\nTotal unique destinations: {len(allowed)}")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Generate a self-learned outbound firewall allowlist (iptables) based "
            "on live traffic."
        ),
    )
    parser.add_argument(
        "--observe-seconds",
        type=int,
        default=30,
        help="How long to watch connections in seconds (default: 30)",
    )
    parser.add_argument(
        "--out",
        type=str,
        default="rules_seal.sh",
        help="Path to write the lockdown script (default: rules_seal.sh)",
    )
    parser.add_argument(
        "--no-drop",
        action="store_true",
        help="If set, do not set OUTPUT policy to DROP (less aggressive)",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def main() -> None:
    """Entry point for net_seal."""
    args = parse_args()

    print(f"[net_seal] Watching outbound connections for {args.observe_seconds} seconds...")
    allowed = observe(args.observe_seconds)

    pretty_preview(allowed)

    out_path = Path(args.out)
    generate_iptables_script(
        allowed,
        out_path,
        default_drop=not args.no_drop,
    )

    print(f"\n[net_seal] Wrote {out_path}")
    print("          Review it. If you really want to enforce it:")
    print(f"          sudo bash {out_path}")
    print("\n[net_seal] IMPORTANT:")
    print("  - This will aggressively lock down outbound traffic.")
    print("  - You can break updates / messaging apps / VPN / etc. if they weren't active during capture.")
    print("  - You are responsible for running it.\n")


if __name__ == "__main__":
    main()

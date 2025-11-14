#!/usr/bin/env python3
"""
IT 359 – Automated Red Team Workflow (Starter Code)

This script:
  1. Parses ScanCannon results
  2. Builds a structured model of hosts + services
  3. Provides hooks for automated follow-up actions

IMPORTANT:
  - Only use this in lab environments (e.g., your Proxmox range).
  - Do NOT point this at networks you don't own / have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Iterable


# -----------------------------
# Data models
# -----------------------------

@dataclass
class Service:
    """Represents a network service on a host."""
    name: str          # e.g., "ssh", "http", "ftp"
    port: int          # e.g., 22, 80
    protocol: str = "tcp"

    def __str__(self) -> str:
        return f"{self.name} ({self.protocol}/{self.port})"


@dataclass
class Host:
    """Represents a host discovered by ScanCannon."""
    ip: str
    ports: Set[int] = field(default_factory=set)
    services: Dict[int, Service] = field(default_factory=dict)

    def add_service(self, service: Service) -> None:
        self.ports.add(service.port)
        self.services[service.port] = service

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "ports": sorted(self.ports),
            "services": [
                {
                    "name": svc.name,
                    "port": svc.port,
                    "protocol": svc.protocol,
                }
                for svc in sorted(self.services.values(), key=lambda s: s.port)
            ],
        }


# -----------------------------
# ScanCannon parsing helpers
# -----------------------------

def parse_hosts_and_ports_file(path: Path) -> Dict[str, Set[int]]:
    """
    Parse hosts_and_ports.txt produced by ScanCannon.

    Expected format (based on ScanCannon docs):
        192.0.2.10:22
        192.0.2.11:80
        192.0.2.11:443

    Returns:
        dict[ip] -> set(ports)
    """
    host_ports: Dict[str, Set[int]] = {}
    if not path.is_file():
        return host_ports

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Usually "IP:PORT" in ScanCannon output
            token = line.split()[0]
            if ":" not in token:
                continue

            ip, port_str = token.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                continue

            host_ports.setdefault(ip, set()).add(port)

    return host_ports


def parse_interesting_servers_dir(path: Path) -> Dict[str, Dict[str, Set[int]]]:
    """
    Parse interesting_servers/ directory.

    Example layout (from ScanCannon README):
        results/
          <cidr_dir>/
            interesting_servers/
              ssh_servers.txt
              http_servers.txt
              ftp_servers.txt
              ...

    Each file is assumed to contain lines like:
        192.0.2.10:22
        192.0.2.11:22

    Returns:
        dict[service_name] -> dict[ip] -> set(ports)
           e.g. { "ssh": { "192.0.2.10": {22}, ... }, "http": {...} }
    """
    service_map: Dict[str, Dict[str, Set[int]]] = {}

    if not path.is_dir():
        return service_map

    for txt_file in path.glob("*.txt"):
        service_name = txt_file.stem.replace("_servers", "")  # ssh_servers -> ssh

        ip_port_map: Dict[str, Set[int]] = {}
        with txt_file.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                token = line.split()[0]
                if ":" not in token:
                    continue

                ip, port_str = token.split(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    continue

                ip_port_map.setdefault(ip, set()).add(port)

        if ip_port_map:
            service_map[service_name] = ip_port_map

    return service_map


def load_scancannon_results(results_root: Path) -> List[Host]:
    """
    Walk the ScanCannon 'results/' directory and produce a list of Host objects.

    Directory structure (from ScanCannon docs):
        results/
          203_0_113_0_24/
            hosts_and_ports.txt
            interesting_servers/
              ssh_servers.txt
              http_servers.txt
              ...

    We:
      1. Parse hosts_and_ports.txt for each network
      2. Parse interesting_servers/ to label services
      3. Merge everything into Host objects
    """
    if not results_root.is_dir():
        raise FileNotFoundError(f"Results directory not found: {results_root}")

    hosts: Dict[str, Host] = {}

    # Each subdirectory under results/ corresponds to a scanned network
    for network_dir in sorted(results_root.iterdir()):
        if not network_dir.is_dir():
            continue

        hosts_and_ports = parse_hosts_and_ports_file(network_dir / "hosts_and_ports.txt")
        interesting_dir = network_dir / "interesting_servers"
        services_by_name = parse_interesting_servers_dir(interesting_dir)

        # First pass: ensure every IP from hosts_and_ports has a Host object
        for ip, ports in hosts_and_ports.items():
            host = hosts.setdefault(ip, Host(ip=ip))
            for port in ports:
                host.ports.add(port)

        # Second pass: add service labels from interesting_servers
        for service_name, ip_map in services_by_name.items():
            for ip, ports in ip_map.items():
                host = hosts.setdefault(ip, Host(ip=ip))
                for port in ports:
                    host.add_service(Service(name=service_name, port=port))

    return list(hosts.values())

def load_service_config(path: Path|None) -> dict:
    default_config = {
        "services": {
            "ssh": {"actions": ["credential_testing"], "tools": []},
            "ftp": {"actions": ["credential_testing"], "tools": []},
            "http": {"actions": ["web_followup"], "tools": []},
            "https": {"actions": ["web_followup"], "tools": []},
        },
        "defaults": {"actions": ["other"], "tools": []},
    }

    if path is None or not path.is_file():
        return default_config
    
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        else:
            print(f"[!] Unsupported config file format: {suffix}. Using default config.")
    except Exception as e:
            print(f"[!] Error loading config file: {e}. Using default config.")
    
# -----------------------------
# Attack workflow hooks (stubs)
# -----------------------------

from collections import defaultdict

def plan_actions_for_host(host: Host, service_config: dict) -> Dict[str, List[Service]]:
    """
    Decide what to do with each host based on its services and the config.

    Config structure (example):
      {
        "services": {
          "ssh":   {"actions": ["credential_testing"], "tools": [...]},
          "http":  {"actions": ["web_followup"],       "tools": [...]},
          ...
        },
        "defaults": {"actions": ["other"], "tools": []}
      }
    """
    services_cfg = service_config.get("services", {})
    defaults_cfg = service_config.get("defaults", {"actions": ["other"], "tools": []})

    plan: Dict[str, List[Service]] = defaultdict(list)

    for svc in host.services.values():
        cfg = services_cfg.get(svc.name, defaults_cfg)
        actions = cfg.get("actions", [])
        for action in actions:
            plan[action].append(svc)

    return dict(plan)



def execute_plan_for_host(
    host: Host,
    plan: Dict[str, List[Service]],
    service_config: dict,
) -> None:
    """
    Placeholder for your automated workflow.

    Uses the config to show which tools are associated with each service/action.
    """
    services_cfg = service_config.get("services", {})
    defaults_cfg = service_config.get("defaults", {"actions": ["other"], "tools": []})

    print(f"\n[+] Host {host.ip}")
    print(f"    Ports: {sorted(host.ports)}")

    if not plan:
        print("    No specific follow-up actions planned.")
        return

    for action_type, services in plan.items():
        print(f"    Action: {action_type}")
        for svc in services:
            svc_cfg = services_cfg.get(svc.name, defaults_cfg)
            tool_ids = svc_cfg.get("tools", [])

            if tool_ids:
                print(f"      -> would process {svc} using tools: {', '.join(tool_ids)}")
            else:
                print(f"      -> would process {svc} (no tools configured)")


# -----------------------------
# CLI + main
# -----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Automated red team workflow starter for ScanCannon results."
    )
    parser.add_argument(
        "--results",
        type=Path,
        required=True,
        help="Path to ScanCannon 'results/' directory",
    )
    parser.add_argument(
        "--dump-json",
        type=Path,
        help="Optional path to write JSON summary of hosts/services.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file for customizing workflow (not implemented).",
    )
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    service_config = load_service_config(args.config)
    hosts = load_scancannon_results(args.results)
    if not hosts:
        print(f"[!] No hosts found under {args.results}")
        return

    print(f"[+] Loaded {len(hosts)} hosts from ScanCannon results.")

    # Optional JSON dump
    if args.dump_json:
        data = [h.to_dict() for h in hosts]
        args.dump_json.parent.mkdir(parents=True, exist_ok=True)
        args.dump_json.write_text(json.dumps(data, indent=2))
        print(f"[+] Wrote JSON summary to {args.dump_json}")

    # Build and "execute" plans
    for host in hosts:
        plan = plan_actions_for_host(host)
        execute_plan_for_host(host, plan)


if __name__ == "__main__":
    main()
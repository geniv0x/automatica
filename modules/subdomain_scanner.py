"""Subdomain discovery via ffuf virtual-host fuzzing."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from modules.base import BaseModule
from modules.hosts_manager import HostsManager

if TYPE_CHECKING:
    from core.target import Target


class SubdomainScanner(BaseModule):

    name = "subdomains"

    WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"

    def __init__(self, auto_calibration: bool = True):
        super().__init__()
        self.auto_calibration = auto_calibration
        self._hosts_manager = HostsManager()

    def run(self, target: Target) -> None:
        if not target.domains:
            self.log.info("No base domains found, skipping subdomain scan")
            return

        base_domains = list(dict.fromkeys(target.domains))
        discovered_subdomains: list[str] = []

        for base_domain in base_domains:
            found = self._scan_domain(base_domain, target)
            if not found:
                continue

            self.log.success(
                f"{base_domain}: discovered {len(found)} subdomain(s)"
            )
            discovered_subdomains.extend(found)

            # keep subdomains on the same /etc/hosts line as the base domain
            self._hosts_manager.ensure_host_aliases(
                target.ip,
                primary_domain=base_domain,
                aliases=[base_domain, *found],
            )

        for subdomain in discovered_subdomains:
            if subdomain not in target.domains:
                target.domains.append(subdomain)

        if discovered_subdomains:
            self.log.success(
                f"Total unique subdomains discovered: {len(set(discovered_subdomains))}"
            )
        else:
            self.log.info("No subdomains discovered via ffuf")

    def _scan_domain(self, base_domain: str, target: Target) -> list[str]:
        output_file = target.output_dir / f"ffuf_subdomains_{base_domain}.json"
        target_url = self._build_target_url(base_domain, target)

        cmd = [
            "ffuf",
            "-w", self.WORDLIST,
            "-u", target_url,
            "-H", f"Host: FUZZ.{base_domain}",
            "-of", "json",
            "-o", str(output_file),
        ]

        if self.auto_calibration:
            cmd.append("-ac")

        self.log.info(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            self.log.error("ffuf not found — install: sudo apt install ffuf")
            return []

        if result.returncode != 0:
            self.log.warning(
                f"ffuf returned code {result.returncode} for {base_domain}"
            )

        if not output_file.exists() or output_file.stat().st_size == 0:
            self.log.warning(f"No ffuf output file for {base_domain}")
            return []

        try:
            data = json.loads(output_file.read_text())
        except json.JSONDecodeError as e:
            self.log.error(f"Failed to parse ffuf JSON ({base_domain}): {e}")
            return []

        subdomains = []
        for result_item in data.get("results", []):
            fuzz_value = result_item.get("input", {}).get("FUZZ", "").strip()
            if not fuzz_value:
                continue

            candidate = f"{fuzz_value}.{base_domain}".lower()
            if candidate == base_domain.lower():
                continue
            subdomains.append(candidate)

        return list(dict.fromkeys(subdomains))

    @staticmethod
    def _build_target_url(base_domain: str, target: Target) -> str:
        http_services = [s for s in target.services if s.is_http]

        if not http_services:
            return f"http://{base_domain}/"

        primary_svc = http_services[0]
        scheme = "https" if primary_svc.port in (443, 8443) else "http"
        if primary_svc.port in (80, 443):
            return f"{scheme}://{base_domain}/"

        return f"{scheme}://{base_domain}:{primary_svc.port}/"

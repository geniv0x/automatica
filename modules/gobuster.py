"""Directory brute-force via gobuster."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from modules.base import BaseModule

if TYPE_CHECKING:
    from core.target import Target


class Gobuster(BaseModule):

    name = "gobuster"

    WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

    def __init__(self, threads: int = 20, status_codes: str = "200,204,301,302,307,401,403"):
        super().__init__()
        self.threads = threads
        self.status_codes = status_codes

    def run(self, target: Target) -> None:
        http_services = [s for s in target.services if s.is_http]

        if not http_services:
            self.log.info("No HTTP services, skipping gobuster")
            return

        urls = self._build_urls(target.domains, http_services, ip_fallback=target.ip)

        if target.domains:
            self.log.info(
                f"Starting directory/file enumeration after subdomain phase on {len(target.domains)} host(s)"
            )

        for url in urls:
            self._scan(url, target)

    def _build_urls(self, domains: list[str], services, ip_fallback: str) -> list[str]:
        urls = []

        for svc in services:
            scheme = "https" if svc.port in (443, 8443) else "http"
            port_suffix = "" if svc.port in (80, 443) else f":{svc.port}"

            hosts = domains if domains else [ip_fallback]
            for host in hosts:
                urls.append(f"{scheme}://{host}{port_suffix}")

        return list(dict.fromkeys(urls))

    def _scan(self, url: str, target: Target) -> None:
        safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")
        output_file = target.output_dir / f"gobuster_{safe_name}.txt"

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", self.WORDLIST,
            "-t", str(self.threads),
            "-s", self.status_codes,
            "-b", "",
            "-k",                        # skip TLS verification
            "-o", str(output_file),
            "--no-error",
        ]

        self.log.info(f"Running: gobuster dir -u {url}")

        try:
            subprocess.run(cmd, check=False)
        except FileNotFoundError:
            self.log.error("gobuster not found — install: sudo apt install gobuster")
            return

        if output_file.exists() and output_file.stat().st_size > 0:
            self.log.success(f"Results saved: {output_file}")
        else:
            self.log.fail(f"No results for {url}")

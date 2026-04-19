"""Manages /etc/hosts entries."""

import subprocess
from pathlib import Path

from modules.base import BaseModule


class HostsManager(BaseModule):

    name = "hosts"

    HOSTS_PATH = Path("/etc/hosts")

    def run(self, target) -> None:
        """Add all discovered domains to /etc/hosts."""
        if not target.domains:
            self.log.info("No domains to add")
            return

        for domain in target.domains:
            self._add_entry(target.ip, domain)

    def _add_entry(self, ip: str, domain: str) -> bool:
        """Add single entry to /etc/hosts via sudo tee."""
        entry = f"{ip}\t{domain}"
        content = self.HOSTS_PATH.read_text()

        if entry in content or f"{ip} {domain}" in content:
            self.log.info(f"Already in /etc/hosts: {entry}")
            return False

        try:
            subprocess.run(
                ["sudo", "tee", "-a", str(self.HOSTS_PATH)],
                input=f"\n{entry}\n",
                text=True, capture_output=True, check=True
            )
            self.log.success(f"/etc/hosts <- {entry}")
            return True
        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to write /etc/hosts: {e}")
            return False

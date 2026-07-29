"""Manages /etc/hosts entries."""

from __future__ import annotations

import subprocess
from pathlib import Path

from modules.base import BaseModule


class HostsManager(BaseModule):

    name = "hosts"

    HOSTS_PATH = Path("/etc/hosts")

    def run(self, target) -> None:
        """Ensure discovered domains are present in one /etc/hosts line for target IP."""
        if not target.domains:
            self.log.info("No domains to add")
            return

        primary_domain = target.domains[0]
        self.ensure_host_aliases(target.ip, primary_domain, target.domains)

    def ensure_host_aliases(self, ip: str, primary_domain: str, aliases: list[str]) -> bool:
        """
        Ensure '/etc/hosts' contains one line for this target with primary + aliases.
        Example:
            10.10.11.1\tresearch.bedside.htb api.research.bedside.htb dev.research.bedside.htb
        """
        if not primary_domain:
            self.log.warning("Primary domain is empty, skipping /etc/hosts update")
            return False

        desired_hosts = self._unique_nonempty([primary_domain, *aliases])

        try:
            lines = self.HOSTS_PATH.read_text().splitlines()
        except Exception as e:
            self.log.error(f"Failed to read {self.HOSTS_PATH}: {e}")
            return False

        changed = False
        updated_lines: list[str] = []
        matched_target_line = False

        for line in lines:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                updated_lines.append(line)
                continue

            no_inline_comment = line.split("#", 1)[0].strip()
            parts = no_inline_comment.split()
            if len(parts) < 2:
                updated_lines.append(line)
                continue

            line_ip, *line_hosts = parts
            if line_ip == ip and primary_domain in line_hosts:
                merged_hosts = self._unique_nonempty([*line_hosts, *desired_hosts])
                rebuilt = f"{ip}\t{' '.join(merged_hosts)}"
                updated_lines.append(rebuilt)
                matched_target_line = True
                changed = changed or rebuilt != line
                self.log.info(f"Updating /etc/hosts line for {primary_domain}")
                continue

            updated_lines.append(line)

        if not matched_target_line:
            new_line = f"{ip}\t{' '.join(desired_hosts)}"
            updated_lines.append(new_line)
            changed = True
            self.log.info(f"Creating new /etc/hosts line: {new_line}")

        if not changed:
            self.log.info(f"Already in /etc/hosts: {ip} -> {' '.join(desired_hosts)}")
            return False

        final_content = "\n".join(updated_lines).rstrip("\n") + "\n"

        return self._write_hosts_file(final_content)

    def _write_hosts_file(self, content: str) -> bool:
        try:
            subprocess.run(
                ["sudo", "tee", str(self.HOSTS_PATH)],
                input=content,
                text=True,
                capture_output=True,
                check=True,
            )
            self.log.success("/etc/hosts updated")
            return True
        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to write /etc/hosts: {e}")
            return False

    @staticmethod
    def _unique_nonempty(values: list[str]) -> list[str]:
        seen = set()
        out = []
        for value in values:
            host = value.strip()
            if not host or host in seen:
                continue
            seen.add(host)
            out.append(host)
        return out

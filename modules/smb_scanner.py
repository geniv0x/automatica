"""SMB share enumeration via netexec (nxc) — guest and null sessions."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from modules.base import BaseModule

if TYPE_CHECKING:
    from core.target import Target


class SmbScanner(BaseModule):

    name = "smb"

    # (label, username, password) — each tried in order against every host
    CREDENTIALS = [
        ("guest", "guest", ""),
        ("null", "", ""),
    ]

    TIMEOUT = 60

    def run(self, target: Target) -> None:
        smb_services = [s for s in target.services if s.is_smb]

        if not smb_services:
            self.log.info("No SMB services found, skipping SMB enumeration")
            return

        ports = ", ".join(str(s.port) for s in smb_services)
        self.log.success(f"SMB detected on port(s): {ports}")

        for label, user, password in self.CREDENTIALS:
            self._enum_shares(target, label, user, password)

    def _enum_shares(
        self, target: Target, label: str, user: str, password: str
    ) -> None:
        cmd = [
            "nxc", "smb", target.ip,
            "-u", user,
            "-p", password,
            "--shares",
        ]

        # mirror what we run, with quoting so empty creds are visible
        printable = (
            f"nxc smb {target.ip} -u '{user}' -p '{password}' --shares"
        )
        self.log.info(f"Running: {printable}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.TIMEOUT
            )
        except FileNotFoundError:
            self.log.error("nxc not found — install: pipx install netexec")
            return
        except subprocess.TimeoutExpired:
            self.log.warning(f"nxc timed out after {self.TIMEOUT}s ({label} session)")
            return

        output = ((result.stdout or "") + (result.stderr or "")).strip()

        out_file = target.output_dir / f"nxc_smb_{label}.txt"
        out_file.write_text(output + "\n")

        if not output:
            self.log.fail(f"SMB {label} session: no output")
            return

        # surface nxc output to the console
        print(output)

        if "[+]" in output:
            shares = self._parse_shares(output)
            if shares:
                self.log.success(
                    f"SMB {label} session: auth OK, "
                    f"{len(shares)} share(s): {', '.join(shares)} -> {out_file}"
                )
            else:
                self.log.success(f"SMB {label} session: auth OK -> {out_file}")
        else:
            self.log.fail(
                f"SMB {label} session: auth failed / no access -> {out_file}"
            )

    @staticmethod
    def _parse_shares(output: str) -> list[str]:
        """Pull share names out of nxc --shares output.

        Data rows look like:
            SMB  10.10.10.10  445  HOST   ADMIN$   READ   Remote Admin
        The 'Share Permissions Remark' header marks where the table starts.
        """
        shares: list[str] = []
        in_table = False
        for line in output.splitlines():
            if "Share" in line and "Permissions" in line:
                in_table = True
                continue
            if not in_table or "-----" in line:
                continue
            parts = line.split()
            # SMB <ip> <port> <host> <share> ...
            if len(parts) >= 5 and parts[0].upper() == "SMB":
                shares.append(parts[4])
        return shares

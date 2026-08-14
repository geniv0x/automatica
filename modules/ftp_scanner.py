"""FTP anonymous-login check + mirror download via wget."""

from __future__ import annotations

import ftplib
import subprocess
from typing import TYPE_CHECKING

from modules.base import BaseModule

if TYPE_CHECKING:
    from core.target import Target


class FtpScanner(BaseModule):

    name = "ftp"

    USER = "anonymous"
    PASSWORD = "anonymous"

    CONNECT_TIMEOUT = 15    # ftplib connect + wget --timeout
    DOWNLOAD_TIMEOUT = 300  # hard cap on a single wget mirror run

    def run(self, target: Target) -> None:
        ftp_services = [s for s in target.services if s.is_ftp]

        if not ftp_services:
            self.log.info("No FTP services found, skipping FTP check")
            return

        for svc in ftp_services:
            self._check_service(target, svc.port)

    def _check_service(self, target: Target, port: int) -> None:
        self.log.info(f"Trying anonymous FTP login on {target.ip}:{port}")

        listing = self._anon_login_and_list(target.ip, port)
        if listing is None:
            self.log.fail(f"FTP {target.ip}:{port}: anonymous login not allowed")
            return

        self.log.success(
            f"FTP {target.ip}:{port}: anonymous login allowed (anonymous:anonymous)"
        )

        listing_file = target.output_dir / f"ftp_listing_{port}.txt"
        listing_file.write_text("\n".join(listing) + "\n")

        if listing:
            print(f"\n[FTP {target.ip}:{port}] anonymous listing (ls -a):")
            for line in listing:
                print(f"  {line}")
        else:
            self.log.info("Login OK but directory listing is empty")

        self._download(target, port)

    def _anon_login_and_list(self, ip: str, port: int) -> list[str] | None:
        """Log in anonymously and list files (including hidden).

        Returns the listing lines, or None if anonymous login is refused
        or the connection fails.
        """
        ftp = ftplib.FTP()
        try:
            ftp.connect(ip, port, timeout=self.CONNECT_TIMEOUT)
        except ftplib.all_errors as e:
            self.log.warning(f"FTP {ip}:{port}: connection failed: {e}")
            return None

        try:
            ftp.login(self.USER, self.PASSWORD)
        except ftplib.all_errors:
            ftp.close()
            return None

        lines: list[str] = []
        try:
            # 'ls -a' maps to LIST -a; some servers ignore the flag, so
            # fall back to a plain listing if the argument form errors out.
            try:
                ftp.dir("-a", lines.append)
            except ftplib.all_errors:
                lines.clear()
                ftp.dir(lines.append)
        except ftplib.all_errors as e:
            self.log.warning(f"FTP {ip}:{port}: listing failed: {e}")
        finally:
            try:
                ftp.quit()
            except ftplib.all_errors:
                ftp.close()

        return lines

    def _download(self, target: Target, port: int) -> None:
        dest = target.output_dir / "downloaded"
        dest.mkdir(parents=True, exist_ok=True)

        host = target.ip if port == 21 else f"{target.ip}:{port}"
        url = f"ftp://{self.USER}:{self.PASSWORD}@{host}"

        # Passive first; only fall back to active if passive pulled nothing.
        # 'wget -m' implies '-N' (timestamping), so re-runs never re-fetch a
        # file that's already on disk — no duplicates even if both modes run.
        self._wget_mirror(target, url, dest, passive=True)
        if self._count_files(dest) == 0:
            self.log.info("Passive mirror got nothing — retrying with --no-passive-ftp")
            self._wget_mirror(target, url, dest, passive=False)

        count = self._count_files(dest)
        if count:
            self.log.success(f"Downloaded {count} file(s) -> {dest}")
        else:
            self.log.fail(f"FTP {target.ip}:{port}: nothing downloaded")

    def _wget_mirror(self, target: Target, url: str, dest, passive: bool) -> None:
        mode = "passive" if passive else "active"
        cmd = [
            "wget", "-m", "-nH",
            "--tries=2",
            f"--timeout={self.CONNECT_TIMEOUT}",
            "-P", str(dest),
        ]
        if not passive:
            cmd.append("--no-passive-ftp")
        cmd.append(url)

        self.log.info(f"Mirroring FTP ({mode}): {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.DOWNLOAD_TIMEOUT
            )
        except FileNotFoundError:
            self.log.error("wget not found — install: sudo apt install wget")
            return
        except subprocess.TimeoutExpired:
            self.log.warning(
                f"wget mirror ({mode}) timed out after {self.DOWNLOAD_TIMEOUT}s"
            )
            return

        log_file = target.output_dir / f"ftp_wget_{mode}.log"
        log_file.write_text((result.stdout or "") + (result.stderr or ""))

    @staticmethod
    def _count_files(dest) -> int:
        """Count downloaded files, ignoring wget's '.listing' artifacts."""
        return sum(
            1 for p in dest.rglob("*")
            if p.is_file() and p.name != ".listing"
        )

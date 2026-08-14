"""NFS export discovery (showmount) and mounting."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from modules.base import BaseModule

if TYPE_CHECKING:
    from core.target import Target


class NfsScanner(BaseModule):

    name = "nfs"

    SHOWMOUNT_TIMEOUT = 30
    MOUNT_TIMEOUT = 30

    # tried in order per export: default NFS version first, then vers=2
    # (some old HTB boxes only speak NFSv2)
    MOUNT_OPTIONS = ("nolock", "nolock,vers=2")

    def run(self, target: Target) -> None:
        nfs_services = [s for s in target.services if s.is_nfs]

        if not nfs_services:
            self.log.info("No NFS services found, skipping NFS check")
            return

        exports = self._showmount(target)
        if not exports:
            self.log.fail(f"No NFS exports listed on {target.ip}")
            return

        self.log.success(
            f"NFS export(s) on {target.ip}: {', '.join(exports)}"
        )

        mnt_root = target.output_dir / "mnt"
        mnt_root.mkdir(parents=True, exist_ok=True)

        for export in exports:
            self._mount_export(target, export, mnt_root)

    def _showmount(self, target: Target) -> list[str]:
        cmd = ["showmount", "-e", target.ip]
        self.log.info(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.SHOWMOUNT_TIMEOUT
            )
        except FileNotFoundError:
            self.log.error("showmount not found — install: sudo apt install nfs-common")
            return []
        except subprocess.TimeoutExpired:
            self.log.warning(f"showmount timed out after {self.SHOWMOUNT_TIMEOUT}s")
            return []

        output = (result.stdout or "").strip()
        (target.output_dir / "showmount.txt").write_text(output + "\n")

        if output:
            print(output)

        exports = []
        for line in output.splitlines():
            line = line.strip()
            # skip the "Export list for <host>:" header
            if not line or line.lower().startswith("export list"):
                continue
            path = line.split()[0]
            if path.startswith("/"):
                exports.append(path)
        return exports

    def _mount_export(self, target: Target, export: str, mnt_root: Path) -> None:
        mountpoint = mnt_root / self._safe_name(export)
        mountpoint.mkdir(parents=True, exist_ok=True)

        if self._is_mounted(mountpoint):
            self.log.info(f"Already mounted: {mountpoint}")
            self._list_mount(mountpoint)
            return

        src = f"{target.ip}:{export}"
        for opts in self.MOUNT_OPTIONS:
            if self._try_mount(src, mountpoint, opts):
                self.log.success(f"Mounted {src} -> {mountpoint} (-o {opts})")
                self._list_mount(mountpoint)
                return

        self.log.fail(f"Failed to mount {src} -> {mountpoint}")

    def _try_mount(self, src: str, mountpoint: Path, opts: str) -> bool:
        cmd = ["mount", "-t", "nfs", src, str(mountpoint), "-o", opts]
        self.log.info(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.MOUNT_TIMEOUT
            )
        except FileNotFoundError:
            self.log.error("mount not found")
            return False
        except subprocess.TimeoutExpired:
            self.log.warning(f"mount timed out (-o {opts})")
            return False

        if result.returncode == 0:
            return True

        err = (result.stderr or "").strip()
        if err:
            self.log.warning(f"mount failed (-o {opts}): {err}")
        return False

    def _list_mount(self, mountpoint: Path) -> None:
        try:
            entries = sorted(p.name for p in mountpoint.iterdir())
        except OSError as e:
            self.log.warning(f"Cannot list {mountpoint}: {e}")
            return

        if not entries:
            self.log.info(f"{mountpoint} is empty")
            return

        print(f"  [NFS {mountpoint}] contents:")
        for name in entries:
            print(f"    {name}")

    @staticmethod
    def _is_mounted(mountpoint: Path) -> bool:
        """True if mountpoint is an active mount (checked via /proc/mounts)."""
        target = str(mountpoint.resolve())
        try:
            with open("/proc/mounts") as f:
                return any(line.split()[1] == target for line in f)
        except OSError:
            return False

    @staticmethod
    def _safe_name(export: str) -> str:
        """Turn an export path into a mountpoint dir name: /home/backup -> home_backup."""
        name = export.strip("/").replace("/", "_")
        return name or "root"

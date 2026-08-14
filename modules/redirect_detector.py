"""HTTP redirect detection and /etc/hosts management."""

import subprocess
import re

from modules.base import BaseModule
from core.models import Service


class RedirectDetector(BaseModule):

    name = "redirect"

    TIMEOUT = 5

    def run(self, target) -> None:
        """Check HTTP services for redirects, update /etc/hosts."""
        http_services = [s for s in target.services if s.is_http]

        if not http_services:
            self.log.info("No HTTP services found, skipping redirect check")
            return

        for svc in http_services:
            domain = self._check_redirect(target.ip, svc)
            if domain and domain not in target.domains:
                target.domains.append(domain)
                self.log.success(f"Port {svc.port} redirects to: {domain}")

    def _check_redirect(self, ip: str, service: Service) -> str | None:
        """Use curl to detect redirect target domain."""
        scheme = "https" if service.port in (443, 8443) else "http"
        url = f"{scheme}://{ip}:{service.port}"

        try:
            result = subprocess.run(
                [
                    "curl", "-s", "-k", "-L",
                    "--max-redirs", "3",
                    "-o", "/dev/null",
                    "-w", "%{url_effective}",
                    "-m", str(self.TIMEOUT),
                    url
                ],
                capture_output=True, text=True
            )
        except FileNotFoundError:
            self.log.error("curl not found")
            return None

        effective_url = result.stdout.strip()
        if not effective_url:
            return None

        match = re.search(r"https?://([^/:]+)", effective_url)
        if not match:
            return None

        domain = match.group(1)

        if domain == ip:
            return None
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            return None

        return domain

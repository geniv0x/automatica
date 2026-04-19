"""Nmap service scan module."""

import subprocess
import xml.etree.ElementTree as ET

from modules.base import BaseModule
from core.models import Service


class NmapScanner(BaseModule):

    name = "nmap"

    def __init__(self, ports: str = "-", timing: str = "4"):
        super().__init__()
        self.ports = ports
        self.timing = timing

    def run(self, target) -> None:
        """Run nmap -sSVC and populate target.services."""
        cmd = [
            "nmap", "-sSVC",
            f"-p{self.ports}",
            f"-T{self.timing}",
            "--open", "-oX", "-",
            target.ip
        ]
        self.log.info(f"Running: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            self.log.error(f"nmap failed:\n{result.stderr}")
            return

        services = self._parse_xml(result.stdout)
        target.services.extend(services)
        self.log.success(f"Found {len(services)} open service(s)")

        # save raw xml
        xml_path = target.output_dir / "nmap_raw.xml"
        xml_path.write_text(result.stdout)

    def _parse_xml(self, xml_output: str) -> list[Service]:
        """Parse nmap XML into Service objects."""
        services = []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            self.log.error(f"XML parse error: {e}")
            return []

        for port_elem in root.iter("port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue

            svc_elem = port_elem.find("service")
            if svc_elem is None:
                continue

            services.append(Service(
                port=int(port_elem.get("portid", 0)),
                proto=port_elem.get("protocol", "tcp"),
                name=svc_elem.get("name", ""),
                product=svc_elem.get("product", ""),
                version=svc_elem.get("version", ""),
                extra_info=svc_elem.get("extrainfo", ""),
            ))

        return services

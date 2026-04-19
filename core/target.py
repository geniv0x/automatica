"""Target orchestrator — runs modules in sequence."""

import json
from pathlib import Path
from datetime import datetime

from core.models import Service
from core.logger import Logger
from modules.base import BaseModule


class Target:
    """Single target IP. Holds state, runs modules."""

    def __init__(self, ip: str, modules: list[BaseModule]):
        self.ip = ip
        self.services: list[Service] = []
        self.domains: list[str] = []
        self.output_dir = Path(f"./results/{ip}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log = Logger()
        self._modules = modules

    def run(self):
        """Execute all modules in order."""
        self.log.info(f"{'='*50}")
        self.log.info(f"TARGET: {self.ip}")
        self.log.info(f"{'='*50}")

        for module in self._modules:
            self.log.info(f"Running module: {module.name}")
            module.run(self)

        self._report()
        self._save()

    def _report(self):
        """Print summary to console."""
        print(f"\n{'='*50}")
        print(f"  REPORT: {self.ip}")
        print(f"  Domains: {', '.join(self.domains) if self.domains else 'none'}")
        print(f"{'='*50}")

        for svc in self.services:
            print(f"\n  {svc}")
            if not svc.exploits:
                print("    -- no known exploits")
                continue
            for exp in svc.exploits:
                print(f"    -- {exp}")

        rce_total = sum(
            1 for s in self.services for e in s.exploits if e.is_rce
        )
        if rce_total:
            print(f"\n  [!!!] Total RCE exploits: {rce_total}")

    def _save(self):
        """Save results as JSON."""
        data = {
            "ip": self.ip,
            "scan_time": datetime.now().isoformat(),
            "domains": self.domains,
            "services": [
                {
                    "port": s.port,
                    "proto": s.proto,
                    "name": s.name,
                    "product": s.product,
                    "version": s.version,
                    "exploits": [
                        {
                            "title": e.title,
                            "path": e.path,
                            "source": e.source,
                            "is_rce": e.is_rce
                        }
                        for e in s.exploits
                    ]
                }
                for s in self.services
            ]
        }

        path = self.output_dir / "scan.json"
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        self.log.success(f"Saved: {path}")

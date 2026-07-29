#!/usr/bin/env python3
"""
CTF Auto-Recon
Usage: sudo python3 main.py <target_ip>
"""

import sys

from core import Target
from modules import (
    NmapScanner,
    RedirectDetector,
    HostsManager,
    ExploitSearcher,
    SubdomainScanner,
    Gobuster,
)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <target_ip>")
        sys.exit(1)

    ip = sys.argv[1]

    # module pipeline — order matters
    modules = [
        NmapScanner(ports="-", timing="4"),
        RedirectDetector(),
        HostsManager(),
        SubdomainScanner(),
        ExploitSearcher(),
        Gobuster(),
    ]

    target = Target(ip=ip, modules=modules)
    target.run()


if __name__ == "__main__":
    main()

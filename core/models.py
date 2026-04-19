"""Data models for scan results."""

from dataclasses import dataclass, field


@dataclass
class Exploit:
    """Single exploit entry from exploit-db or metasploit."""
    title: str
    path: str
    source: str  # "exploitdb" or "msf"

    RCE_INDICATORS = [
        "remote code", "rce", "command execution",
        "reverse shell", "code execution"
    ]

    @property
    def is_rce(self) -> bool:
        title_lower = self.title.lower()
        return any(ind in title_lower for ind in self.RCE_INDICATORS)

    def __str__(self):
        tag = " [RCE]" if self.is_rce else ""
        return f"[{self.source}] {self.title}{tag}  |  {self.path}"


@dataclass
class Service:
    """Single open port / service from nmap."""
    port: int
    proto: str
    name: str
    product: str
    version: str
    extra_info: str = ""
    exploits: list[Exploit] = field(default_factory=list)

    HTTP_PORTS = {80, 443, 8080, 8443}

    @property
    def is_http(self) -> bool:
        return self.port in self.HTTP_PORTS or "http" in self.name.lower()

    @property
    def version_query(self) -> str:
        """Search string for searchsploit."""
        return f"{self.product} {self.version}".strip()

    def __str__(self):
        v = f"{self.product} {self.version}".strip() or "unknown"
        return f"{self.port}/{self.proto} [{self.name}] -> {v}"

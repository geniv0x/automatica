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
    SMB_PORTS = {139, 445}
    SMB_SERVICE_NAMES = ("microsoft-ds", "netbios-ssn", "smb", "samba")
    FTP_PORTS = {21}
    NFS_PORTS = {2049}

    # words nmap appends to products but exploit-db titles usually omit
    # (e.g. 'Apache httpd', 'Microsoft IIS httpd') — dropped in fallback queries
    SEARCH_NOISE_WORDS = {"httpd", "daemon"}

    @property
    def is_http(self) -> bool:
        return self.port in self.HTTP_PORTS or "http" in self.name.lower()

    @property
    def is_smb(self) -> bool:
        name = self.name.lower()
        return self.port in self.SMB_PORTS or any(
            n in name for n in self.SMB_SERVICE_NAMES
        )

    @property
    def is_ftp(self) -> bool:
        return self.port in self.FTP_PORTS or "ftp" in self.name.lower()

    @property
    def is_nfs(self) -> bool:
        return self.port in self.NFS_PORTS or "nfs" in self.name.lower()

    @property
    def version_query(self) -> str:
        """Human-readable product+version, used for logging."""
        return f"{self.product} {self.version}".strip()

    @property
    def search_queries(self) -> list[str]:
        """searchsploit query variants, most-precise first.

        Consumers try them in order and stop at the first that returns
        results. searchsploit ANDs every word in the query, so an extra
        word nmap adds (e.g. 'httpd' in 'Microsoft IIS httpd 7.5') can drop
        the real exploit even though 'Microsoft IIS 7.5' would match. We
        start precise to keep noise low, and only broaden when the precise
        query finds nothing.
        """
        product = self.product.strip()
        if not product:
            return []

        version = self.version.strip()
        if not version:
            return [product]

        first_word = product.split()[0]
        cleaned = " ".join(
            w for w in product.split()
            if w.lower() not in self.SEARCH_NOISE_WORDS
        )

        candidates = [
            f"{product} {version}",     # precise: 'Apache httpd 2.4.49'
            f"{cleaned} {version}",     # drop noise words: 'Microsoft IIS 7.5'
            f"{first_word} {version}",  # first word only: 'Apache 2.4.49'
        ]

        # major.minor as a last resort: '2.4.49' -> 'Apache 2.4'
        parts = version.split(".")
        if len(parts) >= 2:
            candidates.append(f"{first_word} {parts[0]}.{parts[1]}")

        seen = set()
        queries = []
        for q in candidates:
            q = " ".join(q.split())
            if q and q not in seen:
                seen.add(q)
                queries.append(q)
        return queries

    def __str__(self):
        v = f"{self.product} {self.version}".strip() or "unknown"
        return f"{self.port}/{self.proto} [{self.name}] -> {v}"

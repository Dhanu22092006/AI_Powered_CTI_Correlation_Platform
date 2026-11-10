import re, ipaddress
from urllib.parse import urlparse

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?!\w)")
IP_CANDIDATE_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]{0,4}(?![\w:])")

def extract_iocs(text: str):
    found = {}
    def add(kind, value):
        value = value.strip().rstrip(".,);]")
        key = (kind, value.lower())
        found[key] = {"type": kind, "value": value}
    for value in CVE_RE.findall(text):
        add("cve", value.upper())
    for value in URL_RE.findall(text):
        add("url", value)
    for value in HASH_RE.findall(text):
        add("hash", value.lower())
    for value in IP_CANDIDATE_RE.findall(text):
        try:
            add("ip", str(ipaddress.ip_address(value)))
        except ValueError:
            pass
    url_hosts = set()
    for value in URL_RE.findall(text):
        try:
            url_hosts.add(urlparse(value).hostname.lower())
        except Exception:
            pass
    for value in DOMAIN_RE.findall(text):
        if value.lower() not in url_hosts and not value.lower().endswith((".png", ".jpg", ".jpeg", ".pdf")):
            add("domain", value.lower())
    return list(found.values())

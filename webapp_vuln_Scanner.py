from __future__ import annotations
import argparse
import concurrent.futures
import html
import queue
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode

requests.packages.urllib3.disable_warnings()  # avoid SSL warnings on scans

# ---------------- SQLi Patterns ---------------- #
SQLI_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\):",
    r"fatal: password authentication failed",
    r"sqlite[_ ]error",
    r"sql syntax near",
    r"ORA-\d{5}",
    r"MySQL server version for the right syntax",
    r"ODBC SQL Server Driver",
]
SQLI_ERROR_RE = re.compile("|".join(SQLI_ERRORS), re.I)

SQLI_PAYLOADS = [
    "' OR 1=1--",
    '" OR 1=1--',
    ") OR 1=1--",
    "' AND '1'='1",
    "' AND '1'='2",
]

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36"
)

# ---------------- Data Class ---------------- #
@dataclass
class Finding:
    type: str
    url: str
    method: str = "GET"
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    severity: str = "High"
    extra: Dict[str, str] = field(default_factory=dict)

    def to_dict(self):
        return {
            "type": self.type,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "severity": self.severity,
            "extra": self.extra,
        }

# ---------------- Scanner Class ---------------- #
class Scanner:
    def __init__(self, base_url: str, max_pages: int = 50, max_depth: int = 2,
                 timeout: int = 10, threads: int = 8, verify_tls: bool = False):
        self.base_url = self.normalize(base_url)
        self.parsed_base = urlparse(self.base_url)
        self.origin = (self.parsed_base.scheme, self.parsed_base.netloc)
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.threads = threads
        self.verify_tls = verify_tls
        self.visited: Set[str] = set()
        self.to_visit: "queue.Queue[Tuple[str, int]]" = queue.Queue()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.findings: List[Finding] = []
        self.pages_tested = 0

    @staticmethod
    def normalize(u: str) -> str:
        p = urlparse(u)
        if not p.scheme:
            p = p._replace(scheme="http")
        p = p._replace(fragment="")  # strip fragment
        return urlunparse(p)

    def same_origin(self, u: str) -> bool:
        p = urlparse(u)
        return (p.scheme, p.netloc) == self.origin

    def enqueue(self, url: str, depth: int):
        url = self.normalize(url)
        if url not in self.visited and self.same_origin(url):
            self.to_visit.put((url, depth))

    def crawl(self):
        self.enqueue(self.base_url, 0)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = set()
            while not self.to_visit.empty() and self.pages_tested < self.max_pages:
                url, depth = self.to_visit.get()
                if url in self.visited or depth > self.max_depth:
                    continue
                self.visited.add(url)
                futures.add(exe.submit(self.audit_page, url, depth))
            for f in concurrent.futures.as_completed(futures):
                pass

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            return self.session.request(method, url, timeout=self.timeout,
                                        verify=self.verify_tls, allow_redirects=True, **kwargs)
        except requests.RequestException:
            return None

    def get_links(self, base_url: str, soup: BeautifulSoup) -> List[str]:
        links = set()
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            if href.startswith("javascript:"):
                continue
            links.add(urljoin(base_url, href))
        return list(links)

    def audit_page(self, url: str, depth: int):
        self.pages_tested += 1
        resp = self.request("GET", url)
        if not resp or not resp.text:
            return
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        for link in self.get_links(url, soup):
            if len(self.visited) + self.to_visit.qsize() < self.max_pages:
                self.enqueue(link, depth + 1)
        self.test_params(url)
        forms = soup.find_all("form")
        for f in forms:
            self.test_form(url, f)

    def _submit_form(self, page_url: str, form, data: Dict[str, str], method: str) -> Optional[requests.Response]:
        action = form.get("action") or page_url
        target = urljoin(page_url, action)
        if method.upper() == "POST":
            return self.request("POST", target, data=data)
        else:
            return self.request("GET", target, params=data)

    def _extract_form_fields(self, form) -> Dict[str, str]:
        fields = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = inp.get("type", "text").lower()
            if itype in {"submit", "button", "image", "file"}:
                continue
            value = inp.get("value", "test")
            fields[name] = value
        return fields

    def test_form(self, page_url: str, form):
        method = (form.get("method") or "GET").upper()
        fields = self._extract_form_fields(form)
        for name in list(fields.keys()):
            for payload in SQLI_PAYLOADS:
                data = fields.copy()
                data[name] = payload
                resp = self._submit_form(page_url, form, data, method)
                if not resp:
                    continue
                if SQLI_ERROR_RE.search(resp.text or ""):
                    self.findings.append(Finding(
                        type="SQL Injection (Error-Based)",
                        url=resp.url,
                        method=method,
                        parameter=name,
                        severity="High",
                        evidence="Database error signature in response"
                    ))
                    break

    def test_params(self, url: str):
        p = urlparse(url)
        params = dict(parse_qsl(p.query, keep_blank_values=True))
        if not params:
            return
        for k in params:
            for payload in SQLI_PAYLOADS:
                mutated = params.copy()
                mutated[k] = payload
                test_url = p._replace(query=urlencode(mutated, doseq=True))
                resp = self.request("GET", urlunparse(test_url))
                if not resp:
                    continue
                if SQLI_ERROR_RE.search(resp.text or ""):
                    self.findings.append(Finding(
                        type="SQL Injection (Error-Based)",
                        url=resp.url,
                        method="GET",
                        parameter=k,
                        severity="High",
                        evidence="Database error signature in response"
                    ))
                    break

    def summary(self) -> Dict[str, List[Dict]]:
        out = defaultdict(list)
        for f in self.findings:
            out[f.type].append(f.to_dict())
        return out

    def print_report(self):
        by_type = self.summary()
        print("\n================= SQL INJECTION SCAN REPORT =================")
        print(f"Target: {self.base_url}")
        print(f"Pages tested: {self.pages_tested} | Findings: {len(self.findings)}")
        if not self.findings:
            print("No SQL Injection issues detected with the current heuristics.")
            return
        for ftype, items in by_type.items():
            print(f"\n## {ftype} ({len(items)})")
            for it in items:
                print(f"- [{it['severity']}] {it['method']} {it['url']}" +
                      (f" param={it['parameter']}" if it['parameter'] else ""))
                if it.get("evidence"):
                    print(f"  evidence: {it['evidence']}")

    def save_markdown(self, path: str):
        by_type = self.summary()
        lines = []
        lines.append(f"# SQL Injection Scan Report\n")
        lines.append(f"**Target:** {self.base_url}  ")
        lines.append(f"**Pages tested:** {self.pages_tested}  ")
        lines.append(f"**Total findings:** {len(self.findings)}\n")
        if not self.findings:
            lines.append("No SQL Injection vulnerabilities detected.\n")
        for ftype, items in by_type.items():
            lines.append(f"\n## {ftype} ({len(items)})\n")
            for it in items:
                lines.append(f"- **{it['severity']}** — {it['method']} {it['url']}" +
                             (f" param={it['parameter']}" if it['parameter'] else "") +
                             (f" — evidence: {it['evidence']}" if it.get("evidence") else ""))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


# ---------------- CLI ---------------- #
def main():
    parser = argparse.ArgumentParser(description="SQL Injection Vulnerability Scanner")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--max-pages", type=int, default=50)
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--report", help="Save report to Markdown file")
    args = parser.parse_args()

    scanner = Scanner(args.url,
                      max_pages=args.max_pages,
                      max_depth=args.max_depth,
                      timeout=args.timeout,
                      threads=args.threads)
    scanner.crawl()
    scanner.print_report()
    if args.report:
        scanner.save_markdown(args.report)
        print(f"\nReport saved to {args.report}")

if __name__ == "__main__":
    main()

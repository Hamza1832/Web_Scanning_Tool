import requests
from urllib.parse import urljoin

COMMON_DIRS = [
    "admin/",
    "uploads/",
    "backups/",
    "backup/",
    "config/",
    "old/",
    "test/",
    "private"
]

class OpenDirectoryScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.vulnerabilities = []

    def scan(self):
        print("\n[+] Starting Open Directory Scan...")
        for directory in COMMON_DIRS:
            test_url = urljoin(self.base_url, directory)

            try:
                r = requests.get(test_url, timeout=5)

                if r.status_code == 200 and self.is_directory_listening(r.text):
                    self.vulnerabilities.append({
                        "type": "Open Directory",
                        "location": test_url,
                        "risk": "Meduim"
                    })
                    print(f"[!] Open directory found: {test_url}")
            
            except requests.RequestException:
                continue
        return self.vulnerabilities
    
    def is_directory_listening(self, html):
        indicators = [
            "index of /",
            "<title>index of",
            "parent directory"
        ]
        html = html.lower()
        return any(indicator in html for indicator in indicators)
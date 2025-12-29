import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class WebCrawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited_urls = set()
        self.found_forms = []

    def is_internal_link(self, url):
        return urlparse(url).netloc == self.domain or urlparse(url).netloc == ""
    
    def crawl(self, url):
        if url in self.visited_urls:
            return
        
        print(f"[+] Crawling: {url}")
        self.visited_urls.add(url)

        try:
            response = requests.get(url, timeout=5)
        except requests.RequestException:
            return
        
        if "text/html" not in response.headers.get("Content-Type", ""):
            return
        
        soup = BeautifulSoup(response.text, "html.parser")

        # Extract links
        for link in soup.find_all("a", href=True):
            full_url = urljoin(url, link["href"])
            full_url = full_url.split("#")[0]

            if self.is_internal_link(full_url):
                self.crawl(full_url)
        
        #Extract forms
        for form in soup.find_all("form"):
            self.found_forms.append({
                "page": url,
                "action": urljoin(url, form.get("action", "")),
                "method": form.get("method", "get").lower(),
                "inputs": [
                    {
                        "name": input_tag.get("name"),
                        "type": input_tag.get("type", "text")
                    }
                    for input_tag in form.find_all("input")
                ]
            })
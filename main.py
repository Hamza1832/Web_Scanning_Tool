from crawler.crawler import WebCrawler
from scanners.sqli import SQLiScanner
from scanners.xss import XSSScanner
from scanners.csrf import CSRFScanner
from scanners.open_dirs import OpenDirectoryScanner

if __name__ == "__main__":
    target = "http://testphp.vulnweb.com/"

    crawler = WebCrawler(target)
    crawler.crawl(target)

    """
    print("\n[+] Discovered URLs:")
    for url in crawler.visited_urls:
        print(url)

    print("\n[+] Discovered Forms:")
    for form in crawler.found_forms:
        print(form)
    """

    print("\n[+] Starting SQL Injection scan...")
    sqli = SQLiScanner(crawler.visited_urls, crawler.found_forms)
    sqli_results = sqli.scan()

    """
    print("\n[+] SQL Injection Results:")
    for v in vulns:
        print(v)
    """
    print("\n[+] Starting XSS scan...")
    xss = XSSScanner(crawler.visited_urls, crawler.found_forms)
    xss_results = xss.scan()

    print("\n[+] Starting CSRF scan...")
    csrf = CSRFScanner(crawler.found_forms)
    csrf_results = csrf.scan()
    
    print("\n[+] Starting Open Directory Scanner")
    open_dir = OpenDirectoryScanner(target)
    open_dir_results = open_dir.scan()

    print("\n[+] Vulnerabilities Found:")
    for v in sqli_results + xss_results + csrf_results + open_dir_results:
        print(v)
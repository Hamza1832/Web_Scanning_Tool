class CSRFScanner:
    def __init__(self, forms):
        self.forms = forms
        self.vulnerabilities = []

    def scan(self):
        for form in self.forms:
            if form["method"] != "post":
                continue

            if not self.has_csrf_token(form):
                self.vulnerabilities.append({
                    "type": "CSRF",
                    "location" : form["action"],
                    "risk": "Medium",
                    "reason": "POST form without CSRF token"
                })
                print(f"[!] CSRF protection missing: {form['action']}")
        return self.vulnerabilities
    
    def has_csrf_token(self, form):
        token_keywords = ["csrf", "token", "auth", "nonce"]

        for input_field in form["inputs"]:
            name = (input_field.get("name") or "").lower()
            field_type = (input_field.get("type") or "").lower()

            if field_type == "hidden":
                for keyword in token_keywords:
                    if keyword in name:
                        return True
        return False
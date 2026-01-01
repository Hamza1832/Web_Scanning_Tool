from datetime import datetime


class HTMLReport:
    def __init__(self, target, vulnerabilities):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.filename = "scan_report.html"

    def generate(self):
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f4f6f8;
            padding: 20px;
        }}
        h1 {{
            color: #2c3e50;
        }}
        .info {{
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}
        th, td {{
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }}
        th {{
            background-color: #34495e;
            color: white;
        }}
        .high {{ color: red; font-weight: bold; }}
        .medium {{ color: orange; font-weight: bold; }}
        .low {{ color: green; font-weight: bold; }}
    </style>
</head>
<body>

<h1>Web Application Security Scan Report</h1>

<div class="info">
    <p><strong>Target:</strong> {self.target}</p>
    <p><strong>Scan Date:</strong> {datetime.now()}</p>
    <p><strong>Total Issues:</strong> {len(self.vulnerabilities)}</p>
</div>

<table>
    <tr>
        <th>Vulnerability</th>
        <th>Location</th>
        <th>Method / Parameter</th>
        <th>Risk</th>
    </tr>
"""
        for v in self.vulnerabilities:
            risk = v.get("risk", "High")
            risk_class = risk.lower()

            html += f"""
    <tr>
        <td>{v.get("type")}</td>
        <td>{v.get("location")}</td>
        <td>{v.get("parameter", v.get("method", "-"))}</td>
        <td class="{risk_class}">{risk}</td>
    </tr>
"""

        html += """
</table>

<br>
<p><em>This report was generated for educational purposes only.</em></p>

</body>
</html>
"""

        with open(self.filename, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[+] HTML report generated: {self.filename}")

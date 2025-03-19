from jinja2 import Template
import json

class ScanReport:
    def __init__(self, results):
        self.results = results
    
    def display_console(self):
        print("\n[扫描结果]")
        for res in self.results:
            print(f"\nIP: {res['ip']}")
            print(f"开放端口: {', '.join(map(str, res['ports']))}")
            if res['vulnerabilities']:
                print("发现漏洞:")
                for vuln in res['vulnerabilities']:
                    print(f" - {vuln}")
    
    def generate_html(self):
        tpl = Template('''<!DOCTYPE html>
<html>
<head><title>扫描报告</title></head>
<body>
    {% for res in results %}
    <div style="margin:20px;border:1px solid #ccc">
        <h3>{{ res.ip }}</h3>
        <p>开放端口: {{ res.ports|join(', ') }}</p >
        {% if res.vulnerabilities %}
        <h4>漏洞列表:</h4>
        <ul>
            {% for vuln in res.vulnerabilities %}
            <li>{{ vuln }}</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>
    {% endfor %}
</body>
</html>''')
        with open("report.html", "w") as f:
            f.write(tpl.render(results=self.results))
    
    def save_json(self):
        with open("report.json", "w") as f:
            json.dump(self.results, f, indent=2)
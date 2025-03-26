import json
from jinja2 import Template
from datetime import datetime

class ScanReport:
    def __init__(self, results):
        self.results = results
        self.timestamp = datetime.now().isoformat()
    
    def generate(self, output_format='console', output_dir='./reports', no_color=False):
        if output_format == 'json':
            self._save_json(output_dir)
        elif output_format == 'html':
            self._generate_html(output_dir)
        else:
            self._display_console(no_color)
    
    def _display_console(self, no_color):
        for res in self.results:
            print(f"\n[目标] {res['ip']}")
            print(f"开放端口: {', '.join(map(str, res['ports']))}")
            if res['vulnerabilities']:
                print("发现漏洞:")
                for vuln in res['vulnerabilities']:
                    print(f" - {vuln}")
    
    def _save_json(self, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, f"scan_{self.timestamp}.json")
        with open(path, 'w') as f:
            json.dump({
                "timestamp": self.timestamp,
                "results": self.results
            }, f, indent=2)
    
    def _generate_html(self, output_dir):
        tpl = Template('''
        <!DOCTYPE html>
        <html>
        <body>
            {% for res in results %}
            <div class="host">
                <h3>{{ res.ip }}</h3>
                <p>开放端口: {{ res.ports|join(', ') }}</p>
                {% if res.vulnerabilities %}
                <ul>
                    {% for vuln in res.vulnerabilities %}
                    <li>{{ vuln }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endfor %}
        </body>
        </html>
        ''')
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, f"report_{self.timestamp}.html")
        with open(path, 'w') as f:
            f.write(tpl.render(results=self.results))
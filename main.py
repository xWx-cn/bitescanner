from scanner.core.scanner import SecurityScanner
from scanner.utils.risk_warning import display_warning
import argparse

if __name__ == "__main__":
    display_warning()
    
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP/CIDR")
    parser.add_argument("-p", "--ports", nargs="+", type=int, 
                      default=[21,22,80,443,3306,3389], help="Ports to scan")
    parser.add_argument("-o", "--output", choices=['console','json','html'], 
                      default='console', help="Output format")
    args = parser.parse_args()

    scanner = SecurityScanner(args.target, args.ports)
    report = scanner.run_scan()
    
    if args.output == 'json':
        report.save_json()
    elif args.output == 'html':
        report.generate_html()
    else:
        report.display_console()
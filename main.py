import argparse
import os
import yaml
from scanner.core.scanner import SecurityScanner
from scanner.utils.risk_warning import display_warning

def load_config(config_path):
    """兼容旧版YAML/JSON配置"""
    with open(config_path, 'r') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            return yaml.safe_load(f)
        else:  
            import json
            return json.load(f)

if __name__ == "__main__":
    display_warning()
    
    # 参数解析
    parser = argparse.ArgumentParser(
        description="网络漏洞扫描工具", 
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # 基础参数组
    parser.add_argument("-t", "--target", required=True, 
                      help="目标IP/CIDR (例: 192.168.1.1 或 10.0.0.0/24)")
    parser.add_argument("-p", "--ports", type=int, nargs="+", default=[],
                      help="端口列表 (例: 80,443 或 1-1024)")
    parser.add_argument("--top-ports", type=int,
                      help="扫描Nmap前N个常用端口 (覆盖80%服务)")
    
    # 扫描模式组
    parser.add_argument("--scan-type", choices=['syn', 'connect', 'udp'], 
                      default='connect', help="扫描类型")
    parser.add_argument("--threads", type=int, default=100,
                      help="并发线程数")
    parser.add_argument("--timeout", type=float, default=2.0,
                      help="响应超时秒数")
    parser.add_argument("--rate-limit", type=int,
                      help="每秒最大发包数")
    
    # 漏洞检测组
    parser.add_argument("--cve-db", default=os.path.join('data', 'cve_db.json'),
                      help="CVE数据库路径")
    parser.add_argument("--password-list", default=os.path.join('data', 'weak_passwords.txt'),
                      help="弱密码字典路径")
    parser.add_argument("--skip-brute", action='store_true',
                      help="跳过弱密码爆破")
    
    # 输出控制组
    parser.add_argument("-o", "--output", choices=['console','json','html'], 
                      default='console', help="输出格式")
    parser.add_argument("--output-dir", default="./reports",
                      help="报告保存目录")
    parser.add_argument("--no-color", action='store_true',
                      help="禁用控制台颜色")
    
    # 高级功能组
    parser.add_argument("-c", "--config", 
                      help="配置文件路径 (YAML/JSON)")
    
    args = parser.parse_args()
    
    # 配置文件加载
    if args.config:
        config = load_config(args.config)
        for key, value in config.items():
            if not hasattr(args, key):
                raise ValueError(f"无效配置项: {key}")
            setattr(args, key, value)
    
    # 初始化扫描器
    scanner = SecurityScanner(
        target=args.target,
        ports=args.ports,
        scan_type=args.scan_type,
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        cve_db_path=args.cve_db,
        password_list_path=args.password_list,
        skip_brute=args.skip_brute,
        top_ports=args.top_ports
    )
    
    # 执行扫描
    report = scanner.run_scan()
    
    # 生成报告
    report.generate(
        output_format=args.output,
        output_dir=args.output_dir,
        no_color=args.no_color
    )
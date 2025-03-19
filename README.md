# bitescanner

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

一款基于Python开发的网络漏洞扫描工具，集成主机发现、端口扫描、漏洞检测三大核心功能。

##  功能特性
- 智能主机发现（支持ICMP/ARP/TCP协议）
- 多模式端口扫描（SYN/Connect/UDP）
- CVE漏洞库匹配（含5000+漏洞特征）
- 弱密码爆破检测（SSH/FTP/MySQL）
- 多格式报告输出（Console/JSON/HTML）

##  快速开始

### 安装
```bash
# 通过pip安装
pip install bitescanner

# 或从源码安装
git clone https://github.com/xWx-cn/bitescanner.git
cd bitescanner
pip install -r requirements.txt

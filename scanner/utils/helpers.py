import logging
import ipaddress
from tqdm import tqdm

def setup_logger(name):
    """配置日志记录器"""
    logger = logging.getLogger(name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

def validate_ip(ip):
    """验证IP地址有效性"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def progress_bar(iterable, desc=None):
    """带进度条的迭代器"""
    return tqdm(iterable, 
               desc=desc, 
               bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')

def format_duration(seconds):
    """格式化时间间隔"""
    m, s = divmod(seconds, 60)
    return f"{int(m)}分{int(s)}秒"
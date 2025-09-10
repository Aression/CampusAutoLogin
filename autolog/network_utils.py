
import requests
import uuid
import socket
import time
import logging
from constants import CHECK_URLS, MAX_RETRY_ATTEMPTS, RETRY_INTERVAL

def is_internet_connected(timeout: int = 5) -> bool:
    """
    通过访问多个公共服务，进行多次重试来检测互联网连接状态。
    只有当所有服务的所有尝试都失败时，才认为网络未连接。
    """
    for attempt in range(MAX_RETRY_ATTEMPTS):
        logging.info(f"第 {attempt + 1} 次尝试连接到公共网站...")
        for url in CHECK_URLS:
            try:
                requests.get(url, timeout=timeout)
                logging.info(f"✓ 已成功连接到 {url}，网络正常。")
                return True
            except requests.RequestException:
                logging.warning(f"✗ 无法连接到 {url}。")
            except Exception as error:
                logging.error(f"网络检测失败: {error}")

        if attempt < MAX_RETRY_ATTEMPTS - 1:
            logging.info(f"所有网站连接失败，等待 {RETRY_INTERVAL} 秒后重试...")
            time.sleep(RETRY_INTERVAL)
          
    logging.warning("所有网站在多次尝试后均无法连接，判定为网络未连通。")
    return False

def get_current_ip() -> str:
    """
    获取当前设备的IPv4地址。
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip_address = sock.getsockname()[0]
        sock.close()
        return ip_address
    except Exception:
        return '127.0.0.1'

def get_current_mac() -> str:
    """
    获取当前设备的MAC地址，兼容性更强。
    """
    try:
        mac_hex = hex(uuid.getnode()).replace('0x', '')
        return mac_hex.upper()
    except Exception:
        return '000000000000'

def get_network_info() -> dict:
    """
    获取当前网络信息，包括IP、MAC、回调和时间戳。
    """
    timestamp = int(time.time() * 1000)
    network_info = {
        'ip': get_current_ip(),
        'mac': get_current_mac(),
        'callback': f'dr{timestamp % 100000}',
        'timestamp': str(timestamp)
    }
    return network_info





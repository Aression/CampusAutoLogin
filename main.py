"""
校园网自动登录程序
功能：检测网络状态并自动登录校园网
版本：6.2 (GUI配置后自动启动的静默版)
"""

import sys
import os
import time
import requests
import uuid
import socket
import configparser
import winreg
import logging
import logging.handlers

# GUI 库
import tkinter as tk
from tkinter import messagebox

# =============================================================================
# 日志配置
# =============================================================================
LOG_FILE = 'campus_autologin.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
# 将日志输出到文件，以便在后台模式下查看
file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=1024 * 1024, backupCount=5, encoding='utf-8'
)
file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logging.getLogger().addHandler(file_handler)

# =============================================================================
# 配置管理
# =============================================================================

CONFIG_FILE = 'config.ini'

class ConfigManager:
    """管理程序配置和用户凭证"""
    def __init__(self):
        self.config = configparser.ConfigParser()
        # 更新默认配置，增加 Dr.com 认证IP字段
        self.default_config = {
            'User': {
                'account': '',
                'password': ''
            },
            'Network': {
                'dr_com_ip': '10.254.7.4', # 默认的 Dr.com IP
                'success_flag': '"result":1'
            },
            'Run': {
                'check_interval': 100,
                'retry_interval': 5,
                'max_retries': 3,
                'max_failures': 5,
                'long_interval': 300,
                'autostart': False
            }
        }
        
        # 如果配置文件不存在，创建并写入默认配置
        if not os.path.exists(CONFIG_FILE):
            for section, options in self.default_config.items():
                self.config[section] = {k: str(v) for k, v in options.items()}
            self.save_config()
        else:
            # 如果配置文件存在，读取并检查是否有缺失的配置项，如果有则添加
            self.config.read(CONFIG_FILE)
            for section, options in self.default_config.items():
                if section not in self.config:
                    self.config[section] = {}
                for key, value in options.items():
                    if key not in self.config[section]:
                        self.config[section][key] = str(value)
            self.save_config()

    def get_user_credentials(self) -> dict:
        """获取用户凭证"""
        account = self.config.get('User', 'account', fallback='').strip()
        password = self.config.get('User', 'password', fallback='').strip()
        return {'account': account, 'password': password}

    def get_run_config(self) -> dict:
        """获取运行配置"""
        run_config = {
            'check_interval': self.config.getint('Run', 'check_interval', fallback=self.default_config['Run']['check_interval']),
            'retry_interval': self.config.getint('Run', 'retry_interval', fallback=self.default_config['Run']['retry_interval']),
            'max_retries': self.config.getint('Run', 'max_retries', fallback=self.default_config['Run']['max_retries']),
            'max_failures': self.config.getint('Run', 'max_failures', fallback=self.default_config['Run']['max_failures']),
            'long_interval': self.config.getint('Run', 'long_interval', fallback=self.default_config['Run']['long_interval']),
            'autostart': self.config.getboolean('Run', 'autostart', fallback=self.default_config['Run']['autostart'])
        }
        return run_config

    def get_network_config(self) -> dict:
        """获取网络配置"""
        network_config = {
            'dr_com_ip': self.config.get('Network', 'dr_com_ip', fallback=self.default_config['Network']['dr_com_ip']),
            'success_flag': self.config.get('Network', 'success_flag', fallback=self.default_config['Network']['success_flag']),
            'page_titles': {
                'need_login': '上网登录页',
                'already_login': '注销页'
            }
        }
        return network_config
    
    def save_config(self):
        """保存所有配置到文件"""
        with open(CONFIG_FILE, 'w') as f:
            self.config.write(f)

    def update_user_credentials(self, account: str, password: str):
        """更新并保存用户凭证"""
        self.config['User']['account'] = account
        self.config['User']['password'] = password
        self.save_config()

    def update_dr_com_ip(self, ip: str):
        """更新并保存 Dr.com IP"""
        self.config['Network']['dr_com_ip'] = ip
        self.save_config()

    def update_autostart(self, value: bool):
        """更新并保存开机自启设置"""
        self.config['Run']['autostart'] = str(value)
        self.save_config()

# =============================================================================
# 通知与工具模块
# =============================================================================

def show_notification(title: str, message: str):
    """显示系统通知"""
    try:
        from win11toast import toast
        toast(title, message)
    except ImportError:
        logging.warning("无法发送系统通知，请安装 win11toast 库: `pip install win11toast`")
    except Exception as error:
        logging.error(f"无法发送系统通知: {error}")

def is_internet_connected(timeout: int = 5) -> bool:
    """通过访问公共服务检测互联网连接状态"""
    try:
        requests.get("http://www.google.com/generate_204", timeout=timeout)
        return True
    except requests.RequestException:
        return False
    except Exception as error:
        logging.error(f"网络检测失败: {error}")
        return False

def get_current_ip() -> str:
    """获取当前设备的IPv4地址"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip_address = sock.getsockname()[0]
        sock.close()
        return ip_address
    except Exception:
        return '127.0.0.1'

def get_current_mac() -> str:
    """获取当前设备的MAC地址，兼容性更强"""
    try:
        mac_hex = hex(uuid.getnode()).replace('0x', '')
        return mac_hex.upper()
    except Exception:
        return '000000000000'

def get_network_info() -> dict:
    """获取当前网络信息"""
    timestamp = int(time.time() * 1000)
    network_info = {
        'ip': get_current_ip(),
        'mac': get_current_mac(),
        'callback': f'dr{timestamp % 100000}',
        'timestamp': str(timestamp)
    }
    return network_info
    
def set_autostart(enable: bool):
    """设置/取消开机自启（Windows注册表）"""
    if os.name != 'nt':
        logging.warning("此功能仅支持Windows系统。")
        return
    
    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    key = r'Software\Microsoft\Windows\CurrentVersion\Run'
    app_name = 'CampusAutoLogin'
    try:
        reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_ALL_ACCESS)
        if enable:
            winreg.SetValueEx(reg, app_name, 0, winreg.REG_SZ, f'"{exe_path}"')
            logging.info("开机自启已设置")
        else:
            try:
                winreg.DeleteValue(reg, app_name)
                logging.info("开机自启已取消")
            except FileNotFoundError:
                logging.warning("开机自启注册表项不存在，无需取消。")
        winreg.CloseKey(reg)
    except Exception as e:
        logging.error(f"自启设置失败: {e}")

# =============================================================================
# 登录核心逻辑
# =============================================================================

class CampusLoginService:
    """封装登录服务的所有逻辑和状态"""
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.network_config = self.config_manager.get_network_config()
        self.run_config = self.config_manager.get_run_config()
        self.user_credentials = self.config_manager.get_user_credentials()

        # 根据配置的IP动态生成 URL
        self.dr_com_ip = self.network_config.get('dr_com_ip', '')
        self.login_url = f'http://{self.dr_com_ip}/'
        self.login_api = f'http://{self.dr_com_ip}:801/eportal/portal/login'

    def check_login_status(self) -> str:
        """检查当前登录状态"""
        try:
            response = requests.get(self.login_url, timeout=5)
            response.raise_for_status()
            response_text = response.text
            if self.network_config['page_titles']['already_login'] in response_text:
                return 'already_login'
            elif self.network_config['page_titles']['need_login'] in response_text:
                return 'need_login'
            else:
                return 'error'
        except requests.RequestException as e:
            logging.error(f"状态检查请求失败: {e}")
            return 'error'

    def build_login_parameters(self, network_info: dict) -> dict:
        """构建校园网登录参数"""
        login_params = {
            'callback': network_info['callback'],
            'login_method': '1',
            'user_account': f',0,{self.user_credentials["account"]}',
            'user_password': self.user_credentials['password'],
            'wlan_user_ip': network_info['ip'],
            'wlan_user_mac': network_info['mac'],
            'ua': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'term_type': '1',
            'jsVersion': '4.2',
            'terminal_type': '1',
            'lang': 'zh-cn',
            'v': network_info['timestamp'],
        }
        return login_params

    def attempt_login(self, login_params: dict) -> bool:
        """尝试登录校园网"""
        try:
            response = requests.get(
                self.login_api,
                params=login_params,
                timeout=10
            )
            response.raise_for_status()
            return self.network_config['success_flag'] in response.text
        except requests.RequestException as e:
            logging.error(f"登录请求失败: {e}")
            return False

    def login_process(self) -> bool:
        """执行登录流程（包含重试机制）"""
        logging.info("开始校园网登录流程...")
        status = self.check_login_status()
        
        if status == 'already_login':
            logging.info("设备已登录校园网")
            show_notification("登录状态", "设备已登录校园网")
            return True
        elif status == 'error':
            logging.warning("无法访问校园网登录页面，可能未连接到校园网或网络异常。")
            show_notification("网络错误", "无法访问校园网登录页面")
            return False
        
        for attempt in range(1, self.run_config['max_retries'] + 1):
            logging.info(f"第 {attempt} 次登录尝试...")
            try:
                network_info = get_network_info()
                login_params = self.build_login_parameters(network_info)
                if self.attempt_login(login_params):
                    logging.info("校园网登录成功!")
                    show_notification("登录成功", "校园网已连接")
                    return True
                else:
                    logging.warning(f"第 {attempt} 次登录尝试失败")
            except Exception as e:
                logging.error(f"登录过程中发生错误: {e}")
            
            if attempt < self.run_config['max_retries']:
                logging.info(f"等待 {self.run_config['retry_interval']} 秒后重试...")
                time.sleep(self.run_config['retry_interval'])
        
        logging.error(f"登录失败，已重试 {self.run_config['max_retries']} 次")
        show_notification("登录失败", "自动登录已停止，请手动登录")
        return False

    def run_loop(self):
        """主程序循环"""
        consecutive_failures = 0
        while True:
            logging.info(f"开始网络检测...")
            
            if is_internet_connected():
                logging.info("✓ 网络正常，无需操作")
                consecutive_failures = 0
                time.sleep(self.run_config['check_interval'])
                continue
            
            logging.warning("✗ 网络未连通，准备登录校园网...")
            
            if self.login_process():
                consecutive_failures = 0
            else:
                consecutive_failures += 1
                logging.warning(f"登录失败，连续失败次数: {consecutive_failures}")
            
            if consecutive_failures >= self.run_config['max_failures']:
                logging.warning(f"连续失败 {self.run_config['max_failures']} 次，延长检测间隔至 {self.run_config['long_interval']} 秒。")
                time.sleep(self.run_config['long_interval'])
            else:
                time.sleep(self.run_config['check_interval'])

# =============================================================================
# GUI 配置界面
# =============================================================================

class ConfigGUI(tk.Toplevel):
    def __init__(self, master, config_manager):
        super().__init__(master)
        self.master = master
        self.config_manager = config_manager
        self.user_credentials = self.config_manager.get_user_credentials()
        self.network_config = self.config_manager.get_network_config()

        self.title("校园网自动登录程序配置")
        self.geometry("300x250")
        self.resizable(False, False)
        self.attributes('-topmost', True)

        self.create_widgets()

    def create_widgets(self):
        frame = tk.Frame(self, padx=10, pady=10)
        frame.pack(expand=True, fill="both")

        tk.Label(frame, text="账号:").grid(row=0, column=0, sticky="w", pady=5)
        self.account_entry = tk.Entry(frame, width=30)
        self.account_entry.grid(row=0, column=1, pady=5)
        self.account_entry.insert(0, self.user_credentials['account'])

        tk.Label(frame, text="密码:").grid(row=1, column=0, sticky="w", pady=5)
        self.password_entry = tk.Entry(frame, width=30, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)
        self.password_entry.insert(0, self.user_credentials['password'])

        # 新增认证IP输入框
        tk.Label(frame, text="认证IP:").grid(row=2, column=0, sticky="w", pady=5)
        self.ip_entry = tk.Entry(frame, width=30)
        self.ip_entry.grid(row=2, column=1, pady=5)
        self.ip_entry.insert(0, self.network_config['dr_com_ip'])

        self.autostart_var = tk.BooleanVar()
        self.autostart_var.set(self.config_manager.get_run_config()['autostart'])
        self.autostart_check = tk.Checkbutton(frame, text="开机自启", variable=self.autostart_var)
        self.autostart_check.grid(row=3, column=0, columnspan=2, pady=10)

        save_button = tk.Button(frame, text="保存并启动", command=self.save_and_quit)
        save_button.grid(row=4, column=0, columnspan=2, pady=10)

    def save_and_quit(self):
        account = self.account_entry.get().strip()
        password = self.password_entry.get().strip()
        ip = self.ip_entry.get().strip()
        autostart = self.autostart_var.get()

        if not account or not password or not ip:
            messagebox.showerror("错误", "账号、密码和认证IP都不能为空！")
            return

        self.config_manager.update_user_credentials(account, password)
        self.config_manager.update_dr_com_ip(ip)
        self.config_manager.update_autostart(autostart)
        set_autostart(autostart)

        messagebox.showinfo("完成", "配置已保存。")
        self.master.destroy()

# =============================================================================
# 主程序逻辑
# =============================================================================

def run_main_service(config_manager: ConfigManager):
    """主程序后台运行服务"""
    service = CampusLoginService(config_manager)
    try:
        service.run_loop()
    except KeyboardInterrupt:
        logging.info("\n程序被用户中断")
        show_notification("程序停止", "校园网自动登录已停止")
    except Exception as error:
        logging.exception("主程序发生未预期错误")
        show_notification("程序错误", "程序运行异常，请查看日志文件。")

# =============================================================================
# 主程序入口
# =============================================================================

if __name__ == "__main__":
    is_frozen = getattr(sys, 'frozen', False)
    config_manager = ConfigManager()
    user_credentials = config_manager.get_user_credentials()
    network_config = config_manager.get_network_config()

    has_credentials = all(user_credentials.values())
    has_ip = network_config.get('dr_com_ip', '').strip() != ''
    
    # 首次运行或配置不完整时，启动GUI配置界面
    if not has_credentials or not has_ip:
        logging.info("首次运行或配置不完整，启动GUI配置...")
        root = tk.Tk()
        root.withdraw()  # 隐藏主窗口
        ConfigGUI(root, config_manager)
        root.mainloop()
        
        # mainloop结束后，意味着GUI已关闭
        # 此时配置已保存，检查是否可以进入后台服务
        updated_credentials = config_manager.get_user_credentials()
        updated_network_config = config_manager.get_network_config()
        if all(updated_credentials.values()) and updated_network_config.get('dr_com_ip', '').strip():
            logging.info("GUI配置完成，自动启动后台服务。")
            show_notification("程序启动", "校园网自动登录服务已在后台运行")
            run_main_service(config_manager)
        else:
            logging.info("GUI配置未完成或被取消，程序退出。")
            sys.exit(0)
    
    # 已有配置，直接静默启动主循环
    else:
        logging.info("检测到有效配置，将直接启动后台服务...")
        show_notification("程序启动", "校园网自动登录服务已在后台运行")
        run_main_service(config_manager)


import requests
import time
import logging
from config_manager import ConfigManager
from network_utils import get_network_info, is_internet_connected
from notification_manager import show_notification

class CampusLoginService:
    """封装登录服务的所有逻辑和状态"""
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.network_config = self.config_manager.get_network_config()
        self.run_config = self.config_manager.get_run_config()
        self.user_credentials = self.config_manager.get_user_credentials()

        self.dr_com_ip = self.network_config.get("dr_com_ip", "")
        self.login_url = f"http://{self.dr_com_ip}/"
        self.login_api = f"http://{self.dr_com_ip}:801/eportal/portal/login"
      
        self.is_online = False

    def check_login_status(self) -> str:
        """检查当前登录状态"""
        try:
            response = requests.get(self.login_url, timeout=5)
            response.raise_for_status()
            response_text = response.text
            if self.network_config["page_titles"]["already_login"] in response_text:
                return "already_login"
            elif self.network_config["page_titles"]["need_login"] in response_text:
                return "need_login"
            else:
                return "error"
        except requests.RequestException as e:
            logging.error(f"状态检查请求失败: {e}")
            return "error"

    def build_login_parameters(self, network_info: dict) -> dict:
        """构建校园网登录参数"""
        login_params = {
            "callback": network_info["callback"],
            "login_method": "1",
            "user_account": f",0,{self.user_credentials['account']}",
            "user_password": self.user_credentials["password"],
            "wlan_user_ip": network_info["ip"],
            "wlan_user_mac": network_info["mac"],
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "term_type": "1",
            "jsVersion": "4.2",
            "terminal_type": "1",
            "lang": "zh-cn",
            "v": network_info["timestamp"],
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
            return self.network_config["success_flag"] in response.text
        except requests.RequestException as e:
            logging.error(f"登录请求失败: {e}")
            return False

    def login_process(self) -> bool:
        """执行登录流程（包含重试机制）"""
        logging.info("开始校园网登录流程...")
      
        for attempt in range(1, self.run_config["max_retries"] + 1):
            logging.info(f"第 {attempt} 次登录尝试...")
            try:
                network_info = get_network_info()
                login_params = self.build_login_parameters(network_info)
                if self.attempt_login(login_params):
                    logging.info("校园网登录成功!")
                    return True
                else:
                    logging.warning(f"第 {attempt} 次登录尝试失败")
            except Exception as e:
                logging.error(f"登录过程中发生错误: {e}")
          
            if attempt < self.run_config["max_retries"]:
                logging.info(f"等待 {self.run_config['retry_interval']} 秒后重试...")
                time.sleep(self.run_config["retry_interval"])
      
        logging.error(f"登录失败，已重试 {self.run_config['max_retries']} 次")
        show_notification("登录失败", "自动登录已停止，请手动登录", tag="login_fail")
        return False

    def run_loop(self):
        """主程序循环"""
        while True:
            current_is_online = is_internet_connected()
          
            if current_is_online:
                if not self.is_online:
                    logging.info("网络已恢复连接")
                    show_notification("网络状态", "互联网已恢复连接", tag="network_restored")
                self.is_online = True
            else:
                if self.is_online:
                    logging.warning("网络连接已断开")
                    show_notification("网络状态", "互联网连接已断开", tag="network_dropped")
                self.is_online = False
              
                if not self.is_online:
                    self.login_process()
          
            time.sleep(self.run_config["check_interval"])



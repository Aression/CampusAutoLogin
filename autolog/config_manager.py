
import configparser
import os
from constants import CONFIG_FILE, DEFAULT_DR_COM_IP, DEFAULT_LOG_PATH, DEFAULT_CHECK_INTERVAL, DEFAULT_RETRY_INTERVAL, DEFAULT_MAX_RETRIES, DEFAULT_AUTOSTART, SUCCESS_FLAG, NEED_LOGIN_PAGE_TITLE, ALREADY_LOGIN_PAGE_TITLE

class ConfigManager:
    """管理程序配置和用户凭证"""
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.default_config = {
            'User': {
                'account': '',
                'password': ''
            },
            'Network': {
                'dr_com_ip': DEFAULT_DR_COM_IP,
                'success_flag': SUCCESS_FLAG,
                'page_titles_need_login': NEED_LOGIN_PAGE_TITLE,
                'page_titles_already_login': ALREADY_LOGIN_PAGE_TITLE
            },
            'Run': {
                'check_interval': DEFAULT_CHECK_INTERVAL,
                'retry_interval': DEFAULT_RETRY_INTERVAL,
                'max_retries': DEFAULT_MAX_RETRIES,
                'autostart': DEFAULT_AUTOSTART,
                'log_path': DEFAULT_LOG_PATH
            }
        }
      
        if not os.path.exists(CONFIG_FILE):
            for section, options in self.default_config.items():
                self.config[section] = {k: str(v) for k, v in options.items()}
            self.save_config()
        else:
            self.config.read(CONFIG_FILE, encoding='utf-8')
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
            'autostart': self.config.getboolean('Run', 'autostart', fallback=self.default_config['Run']['autostart'])
        }
        return run_config

    def get_network_config(self) -> dict:
        """获取网络配置"""
        network_config = {
            'dr_com_ip': self.config.get('Network', 'dr_com_ip', fallback=self.default_config['Network']['dr_com_ip']),
            'success_flag': self.config.get('Network', 'success_flag', fallback=self.default_config['Network']['success_flag']),
            'page_titles': {
                'need_login': self.config.get('Network', 'page_titles_need_login', fallback=self.default_config['Network']['page_titles_need_login']),
                'already_login': self.config.get('Network', 'page_titles_already_login', fallback=self.default_config['Network']['page_titles_already_login'])
            }
        }
        return network_config
  
    def get_log_path(self) -> str:
        """获取日志路径"""
        return self.config.get('Run', 'log_path', fallback=self.default_config['Run']['log_path'])
  
    def save_config(self):
        """保存所有配置到文件"""
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
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

    def update_log_path(self, path: str):
        """更新并保存日志路径"""
        self.config['Run']['log_path'] = path
        self.save_config()



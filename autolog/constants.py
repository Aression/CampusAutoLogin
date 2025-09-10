
import os

# 日志配置
LOG_FILE_NAME = 'campus_autologin.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'

# 配置管理
CONFIG_FILE = 'config.ini'

# 网络检测
CHECK_URLS = ["http://www.bing.com", "http://www.baidu.com"]
MAX_RETRY_ATTEMPTS = 3
RETRY_INTERVAL = 1 # 秒

# Dr.com 默认IP
DEFAULT_DR_COM_IP = '10.254.7.4'
SUCCESS_FLAG = '"result":1'
NEED_LOGIN_PAGE_TITLE = '上网登录页'
ALREADY_LOGIN_PAGE_TITLE = '注销页'

# 运行配置默认值
DEFAULT_CHECK_INTERVAL = 100 # 秒
DEFAULT_RETRY_INTERVAL = 5 # 秒
DEFAULT_MAX_RETRIES = 3
DEFAULT_AUTOSTART = False
DEFAULT_LOG_PATH = os.getcwd()



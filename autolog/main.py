
import sys
import os
import logging
import logging.handlers
import tkinter as tk

from config_manager import ConfigManager
from campus_login_service import CampusLoginService
from notification_manager import show_notification
from gui import ConfigGUI
from constants import LOG_FILE_NAME, LOG_FORMAT

# =============================================================================
# 日志配置
# =============================================================================
def setup_logging(log_dir: str):
    """
    配置日志系统，将日志输出到指定文件。
    如果指定目录不存在，则创建。
    """
    # 确保日志目录存在
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
      
    log_file_path = os.path.join(log_dir, LOG_FILE_NAME)
  
    # 重置现有日志处理器
    for handler in logging.getLogger().handlers[:]:
        logging.getLogger().removeHandler(handler)

    # 将日志输出到文件，以便在后台模式下查看
    file_handler = logging.handlers.RotatingFileHandler(
        log_file_path, maxBytes=1024 * 1024, backupCount=5, encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
  
    # 配置根日志器
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, handlers=[file_handler])


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
        show_notification("程序停止", "校园网自动登录已停止", tag="shutdown")
    except Exception as error:
        logging.exception("主程序发生未预期错误")
        show_notification("程序错误", "程序运行异常，请查看日志文件。", tag="error")

# =============================================================================
# 主程序入口
# =============================================================================

if __name__ == "__main__":
    config_manager = ConfigManager()
  
    # 在GUI界面启动前先配置日志，确保日志正常工作
    setup_logging(config_manager.get_log_path())
  
    user_credentials = config_manager.get_user_credentials()
    network_config = config_manager.get_network_config()

    has_credentials = all(user_credentials.values())
    has_ip = network_config.get('dr_com_ip', '').strip() != ''
  
    # 首次运行或配置不完整时，启动GUI配置界面
    if (not has_credentials) or (not has_ip):
        logging.info("首次运行或配置不完整，启动GUI配置...")
        root = tk.Tk()
        root.withdraw() # 隐藏主窗口
        ConfigGUI(root, config_manager)
        root.mainloop()
      
        # mainloop结束后，意味着GUI已关闭
        # 此时配置已保存，检查是否可以进入后台服务
        updated_credentials = config_manager.get_user_credentials()
        updated_network_config = config_manager.get_network_config()
        updated_log_path = config_manager.get_log_path()
        if all(updated_credentials.values()) and updated_network_config.get('dr_com_ip', '').strip() and updated_log_path:
            logging.info("GUI配置完成，自动启动后台服务。")
            show_notification("程序启动", "校园网自动登录服务已在后台运行", tag="startup")
            # 重新配置日志，使用新的路径
            setup_logging(updated_log_path)
            run_main_service(config_manager)
        else:
            logging.info("GUI配置未完成或被取消，程序退出。")
            sys.exit(0)
  
    # 已有配置，直接静默启动主循环
    else:
        logging.info("检测到有效配置，将直接启动后台服务...")
        show_notification("程序启动", "校园网自动登录服务已在后台运行", tag="startup")
        run_main_service(config_manager)



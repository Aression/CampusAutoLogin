
import time
import logging

class NotificationManager:
    """管理系统通知的发送，包括去重和冷却。"""
    def __init__(self):
        self.last_notified = {}
        self.cooldown = 60  # 1分钟
      
        self.toast_func = None
        self.is_available = False
        try:
            from win11toast import toast as win11_toast
            self.toast_func = win11_toast
            self.is_available = True
        except ImportError:
            logging.warning("无法发送系统通知，请安装 win11toast 库: `pip install win11toast`")
        except Exception as error:
            logging.error(f"初始化系统通知失败: {error}")

    def send(self, title: str, message: str, tag: str = None):
        """
        发送系统通知，并应用冷却策略。
        :param title: 通知标题
        :param message: 通知消息
        :param tag: (可选) 用于去重的标签。如果未提供，则使用 title 作为标签。
        """
        if not self.is_available:
            return

        notification_tag = tag if tag else title
        current_time = time.time()
      
        if notification_tag in self.last_notified and \
           current_time - self.last_notified[notification_tag] < self.cooldown:
            logging.info(f"通知 \'{title}\' 在冷却期内，已抑制。")
            return

        self.last_notified[notification_tag] = current_time
        try:
            self.toast_func(title, message)
            logging.info(f"已发送通知: {title} - {message}")
        except Exception as e:
            logging.error(f"发送系统通知失败: {e}")

# 全局 NotificationManager 实例
notification_manager = NotificationManager()

def show_notification(title: str, message: str, tag: str = None):
    """
    系统通知门面函数。调用全局管理器发送通知。
    :param title: 通知标题
    :param message: 通知消息
    :param tag: (可选) 用于去重的标签。
    """
    notification_manager.send(title, message, tag)



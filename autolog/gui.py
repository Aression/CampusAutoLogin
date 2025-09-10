
import tkinter as tk
from tkinter import messagebox, filedialog
import os
import sys
import winreg
import logging

from config_manager import ConfigManager

def set_autostart(enable: bool):
    """设置/取消开机自启（Windows注册表）"""
    if os.name != 'nt':
        logging.warning("此功能仅支持Windows系统。")
        return
  
    exe_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    key = r'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
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

class ConfigGUI(tk.Toplevel):
    def __init__(self, master, config_manager: ConfigManager):
        super().__init__(master)
        self.master = master
        self.config_manager = config_manager
        self.user_credentials = self.config_manager.get_user_credentials()
        self.network_config = self.config_manager.get_network_config()
        self.run_config = self.config_manager.get_run_config()

        self.title("校园网自动登录程序配置")
        self.geometry("350x350") # 调整窗口大小以适应新增控件
        self.resizable(False, False)
        self.attributes('-topmost', True)

        self.create_widgets()

    def create_widgets(self):
        frame = tk.Frame(self, padx=10, pady=10)
        frame.pack(expand=True, fill="both")

        tk.Label(frame, text="账号:").grid(row=0, column=0, sticky="w", pady=5)
        self.account_entry = tk.Entry(frame, width=35)
        self.account_entry.grid(row=0, column=1, pady=5)
        self.account_entry.insert(0, self.user_credentials['account'])

        tk.Label(frame, text="密码:").grid(row=1, column=0, sticky="w", pady=5)
        self.password_entry = tk.Entry(frame, width=35, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)
        self.password_entry.insert(0, self.user_credentials['password'])

        tk.Label(frame, text="认证IP:").grid(row=2, column=0, sticky="w", pady=5)
        self.ip_entry = tk.Entry(frame, width=35)
        self.ip_entry.grid(row=2, column=1, pady=5)
        self.ip_entry.insert(0, self.network_config['dr_com_ip'])

        tk.Label(frame, text="日志路径:").grid(row=3, column=0, sticky="w", pady=5)
        self.log_path_entry = tk.Entry(frame, width=25)
        self.log_path_entry.grid(row=3, column=1, sticky="w", pady=5)
        self.log_path_entry.insert(0, self.config_manager.get_log_path())

        self.browse_button = tk.Button(frame, text="浏览", command=self.browse_log_path)
        self.browse_button.grid(row=3, column=1, sticky="e", padx=(0, 5), pady=5)

        self.autostart_var = tk.BooleanVar(value=self.run_config['autostart'])
        self.autostart_check = tk.Checkbutton(frame, text="开机自启", variable=self.autostart_var)
        self.autostart_check.grid(row=4, column=0, columnspan=2, sticky="w", pady=5)

        save_button = tk.Button(frame, text="保存配置", command=self.save_and_exit)
        save_button.grid(row=5, column=0, columnspan=2, pady=10)

    def browse_log_path(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.log_path_entry.delete(0, tk.END)
            self.log_path_entry.insert(0, folder_selected)

    def save_and_exit(self):
        account = self.account_entry.get()
        password = self.password_entry.get()
        dr_com_ip = self.ip_entry.get()
        log_path = self.log_path_entry.get()
        autostart = self.autostart_var.get()

        if not account or not password or not dr_com_ip or not log_path:
            messagebox.showerror("错误", "所有字段都不能为空！")
            return

        self.config_manager.update_user_credentials(account, password)
        self.config_manager.update_dr_com_ip(dr_com_ip)
        self.config_manager.update_log_path(log_path)
        self.config_manager.update_autostart(autostart)
        set_autostart(autostart)

        messagebox.showinfo("完成", "配置已保存。")
        self.master.destroy()



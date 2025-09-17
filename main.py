import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import ssl
import requests
import json
import threading
import logging
from PIL import Image, ImageTk
from ldap3 import Server, Connection, ALL, Tls, SUBTREE

logging.basicConfig(filename='assistant.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')

BG_COLOR, TEXT_COLOR, ACCENT_COLOR, ENTRY_BG_COLOR, BUTTON_BG_COLOR, BUTTON_HOVER_COLOR = "#282c34", "#abb2bf", "#61afef", "#1e2127", "#3a4049", "#4a515c"
FONT_NORMAL = ("Microsoft JhengHei", 10)
FONT_BOLD = ("Microsoft JhengHei", 12, "bold")
FONT_MONO = ("Consolas", 10)


# 全域設定
ASSISTANT_WEBHOOKS = {
    "policy": "http://192.168.88.43:5678/webhook/OpenWebUIAdminAgent",
    "erp": "YOUR_ERP_ASSISTANT_WEBHOOK_URL",
    "it": "YOUR_IT_ASSISTANT_WEBHOOK_URL",
}

# AD 設定
# --- 設定區 ---
AD_SERVER = '192.168.88.12'
AD_DOMAIN = 'locus-cell.com'
AD_SEARCH_BASE = 'DC=locus-cell,DC=com'
# 【修改點】改用 LDAPS 的標準 Port 636
AD_PORT = 636
# 【修改點】啟用 SSL/TLS 加密連線
USE_SSL = True


def parse_group_name(dn_string):
    try: return dn_string.split(',')[0].split('=')[1]
    except IndexError: return None

def authenticate_ad_and_get_groups(username, password):
    logging.info(f"User '{username}' is attempting to log in.")
    user_principal_name = f'{username}@{AD_DOMAIN}' if '@' not in username else username
    if not password:
        logging.warning(f"Login attempt for '{username}' failed: Password was empty.")
        return False, "密碼不可為空", None
    try:
        tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        server = Server(AD_SERVER, port=AD_PORT, use_ssl=USE_SSL, get_info=ALL, tls=tls_config)
        conn = Connection(server, user=user_principal_name, password=password, auto_bind=True)
        if not conn.bound:
            logging.warning(f"Login failed for '{username}': Invalid credentials. Result: {conn.result}")
            return False, f"驗證失敗: {conn.result}", None
        conn.search(search_base=AD_SEARCH_BASE, search_filter=f'(&(objectClass=user)(sAMAccountName={username}))', search_scope=SUBTREE, attributes=['memberOf'])
        if conn.entries:
            groups = [parse_group_name(dn) for dn in conn.entries[0].memberOf.values if parse_group_name(dn)]
            user_data = {"username": username, "groups": groups}
            conn.unbind()
            logging.info(f"User '{username}' logged in successfully. Groups: {groups}")
            return True, "驗證成功", user_data
        else:
            conn.unbind()
            logging.error(f"Auth success for '{username}', but couldn't find user entry.")
            return False, "驗證成功，但找不到使用者資訊。", None
    except Exception as e:
        logging.error(f"Exception during login for '{username}': {e}", exc_info=True)
        return False, f"發生錯誤: {e}", None

class MainWindow(tk.Toplevel):
    def __init__(self, user_data, login_window):
        super().__init__()
        self.user_data, self.login_window = user_data, login_window
        self.username = user_data.get("username", "未知使用者")
        self.user_groups = user_data.get("groups", [])
        self.initialized_tabs = set()
        self.title("樂迦小幫手")
        self.geometry("700x550")
        self.configure(bg=BG_COLOR)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        try:
            send_icon_image = Image.open("send_icon.png").resize((20, 20), Image.Resampling.LANCZOS)
            self.send_icon = ImageTk.PhotoImage(send_icon_image)
            # 重新載入頭像
            avatar_image = Image.open("avatar.png").resize((40, 40), Image.Resampling.LANCZOS)
            self.avatar_icon = ImageTk.PhotoImage(avatar_image)
        except FileNotFoundError as e:
            self.send_icon, self.avatar_icon = None, None
            logging.warning(f"{e.filename} not found.")

        tk.Label(self, text=f"歡迎, {self.username}！", font=FONT_BOLD, bg=BG_COLOR, fg=ACCENT_COLOR).pack(pady=10)
        
        style = ttk.Style(); style.theme_use('default')
        style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
        style.configure("TNotebook.Tab", background=BUTTON_BG_COLOR, foreground=TEXT_COLOR, padding=[10, 5], font=FONT_NORMAL)
        style.map("TNotebook.Tab", background=[("selected", ACCENT_COLOR)], foreground=[("selected", BG_COLOR)])
        style.configure("Custom.TFrame", background=BG_COLOR)

        self.notebook = ttk.Notebook(self, style="TNotebook")
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)
        self.tab_widgets = self.create_dynamic_tabs()
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_selected)
        self.after(100, self.on_tab_selected)

        if not self.notebook.tabs():
            tk.Label(self, text="您目前沒有任何助理的使用權限...", font=FONT_NORMAL, fg="red", bg=BG_COLOR).pack(pady=20)

    def on_closing(self):
        logging.info(f"User '{self.username}' closed application."); self.login_window.destroy()

    def create_dynamic_tabs(self):
        tab_widgets_map = {}
        ASSISTANT_MAPPING = {"G_Assistant_PolicyUsers": {"name": "行政助理", "webhook_key": "policy"}, "G_Assistant_ERPUsers": {"name": "ERP助理", "webhook_key": "erp"}, "G_Assistant_ITUsers": {"name": "IT助理", "webhook_key": "it"}}
        for group, info in ASSISTANT_MAPPING.items():
        #    if group in self.user_groups:
                widgets = self.create_assistant_tab(info["name"], info["webhook_key"])
                tab_widgets_map[info["name"]] = {"widgets": widgets, "webhook_key": info["webhook_key"]}
        return tab_widgets_map

    def create_assistant_tab(self, name, webhook_key):
        frame = ttk.Frame(self.notebook, style="Custom.TFrame"); self.notebook.add(frame, text=name)
        frame.columnconfigure(0, weight=1)
        answer_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=FONT_MONO, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, relief="flat", insertbackground=TEXT_COLOR, spacing1=5, spacing3=5, padx=10, pady=5)
        answer_text.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=10, pady=(0,5)); frame.rowconfigure(0, weight=1)
        
        answer_text.tag_configure("user_paragraph", justify="right")
        answer_text.tag_configure("assistant_paragraph", justify="left")
        answer_text.tag_configure("user_tag", foreground=ACCENT_COLOR, font=(FONT_MONO[0], FONT_MONO[1], 'bold'))
        answer_text.tag_configure("assistant_tag", foreground="#da70d6", font=(FONT_MONO[0], FONT_MONO[1], 'bold'))
        answer_text.config(state="disabled")

        query_entry = tk.Entry(frame, font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat")
        query_entry.grid(row=1, column=0, sticky="ew", padx=(10, 5), ipady=8)
        query_button = tk.Button(frame, text=" 發送", font=FONT_NORMAL, bg=BUTTON_BG_COLOR, fg=TEXT_COLOR, activebackground=ACCENT_COLOR, activeforeground=BG_COLOR, relief="flat", padx=10, compound="left", image=self.send_icon)
        query_button.grid(row=1, column=1, sticky="ew", padx=(0, 10), ipady=4)
        status_label = tk.Label(frame, text="", font=("Microsoft JhengHei", 9), bg=BG_COLOR, fg=TEXT_COLOR)
        status_label.grid(row=2, column=0, columnspan=2, sticky="w", padx=10)

        def on_enter(e): query_button['background'] = BUTTON_HOVER_COLOR
        def on_leave(e): query_button['background'] = BUTTON_BG_COLOR
        query_button.bind("<Enter>", on_enter); query_button.bind("<Leave>", on_leave)

        command_func = lambda: self.start_assistant_query(query_entry, answer_text, query_button, status_label, webhook_key, name)
        query_button.config(command=command_func); query_entry.bind("<Return>", lambda e: command_func())
        return {"query_entry": query_entry, "answer_text": answer_text, "query_button": query_button, "status_label": status_label}

    def on_tab_selected(self, event=None):
        if not self.notebook.tabs(): return
        selected_tab_name = self.notebook.tab(self.notebook.select(), "text")
        
        if selected_tab_name not in self.initialized_tabs:
            self.initialized_tabs.add(selected_tab_name)
            tab_info = self.tab_widgets.get(selected_tab_name)
            if tab_info:
                self.add_message_to_log(tab_info["widgets"]["answer_text"], selected_tab_name, f"您好！我是 {selected_tab_name}，請問有什麼可以為您服務的嗎？")

    def add_message_to_log(self, text_widget, sender, message, use_typewriter=False):
        text_widget.config(state="normal")
        if text_widget.get("1.0", tk.END).strip(): text_widget.insert(tk.END, '\n\n')
        
        sender_tag = "user_tag" if sender == "You" else "assistant_tag"
        paragraph_tag = "user_paragraph" if sender == "You" else "assistant_paragraph"
        start_index = text_widget.index(f"{tk.END}-1c")
        
        if sender != "You" and self.avatar_icon:
            text_widget.insert(tk.END, ' ')
            text_widget.image_create(tk.END, image=self.avatar_icon, padx=5)
            text_widget.insert(tk.END, ' ')

        text_widget.insert(tk.END, f"{sender}: ", sender_tag)
        message_start_index = text_widget.index(tk.END)
        
        if use_typewriter: self.typewriter_effect(text_widget, message, 0, message_start_index)
        else: text_widget.insert(tk.END, message)
        
        end_index = text_widget.index(f"{tk.END}-1c")
        text_widget.tag_add(paragraph_tag, start_index, end_index)
        text_widget.see(tk.END); text_widget.config(state="disabled")

    def start_assistant_query(self, query_entry, answer_text, query_button, status_label, webhook_key, assistant_name):
        query = query_entry.get().strip()
        if not query: return
        self.add_message_to_log(answer_text, "You", query)
        query_entry.delete(0, tk.END)
        query_button.config(state="disabled"); query_entry.config(state="disabled")
        status_label.config(text="助理正在思考中...")
        webhook_url = ASSISTANT_WEBHOOKS.get(webhook_key)
        if not webhook_url or "YOUR_" in webhook_url:
            self.add_message_to_log(answer_text, assistant_name, "設定錯誤：Webhook URL 尚未設定！")
            query_button.config(state="normal"); query_entry.config(state="normal"); status_label.config(text="")
            return
        logging.info(f"User '{self.username}' querying '{webhook_key}': '{query}'")
        thread = threading.Thread(target=self.perform_assistant_query, args=(query, webhook_url, answer_text, query_button, query_entry, status_label, webhook_key, assistant_name), daemon=True)
        thread.start()

    def perform_assistant_query(self, query, webhook_url, answer_text, query_button, query_entry, status_label, webhook_key, assistant_name):
        try:
            payload = {"query": query}
            response = requests.post(webhook_url, json=payload, headers={'Content-Type': 'application/json'}, timeout=30)
            response.raise_for_status()
            answer = response.json().get("output", "n8n 回應中未找到 'output' 欄位。")
            logging.info(f"Webhook call for '{webhook_key}' succeeded.")
        except Exception as e:
            answer = f"與後端服務溝通時發生錯誤。\n錯誤詳情: {e}"
            logging.error(f"Webhook call for '{webhook_key}' failed: {e}", exc_info=True)
        self.after(0, self.update_ui_after_query, answer, answer_text, query_button, query_entry, status_label, assistant_name)

    def update_ui_after_query(self, answer, answer_text, query_button, query_entry, status_label, assistant_name):
        status_label.config(text="")
        self.add_message_to_log(answer_text, assistant_name, answer, use_typewriter=True)
        query_button.config(state="normal"); query_entry.config(state="normal"); query_entry.focus()

    def typewriter_effect(self, text_widget, text, index, start_index):
        if index < len(text):
            text_widget.config(state="normal")
            insert_pos = text_widget.index(f"{start_index} + {index}c")
            text_widget.insert(insert_pos, text[index])
            text_widget.see(tk.END); text_widget.config(state="disabled")
            self.after(25, self.typewriter_effect, text_widget, text, index + 1, start_index)

class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("樂迦小幫手 -  帳號登入"); self.geometry("350x250"); self.resizable(False, False); self.configure(bg=BG_COLOR)
        tk.Label(self, text="樂迦小幫手", font=FONT_BOLD, bg=BG_COLOR, fg=ACCENT_COLOR).pack(pady=(20, 10))
        tk.Label(self, text="帳號:", font=FONT_NORMAL, bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=(5,0))
        self.username_entry = tk.Entry(self, width=30, font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat")
        self.username_entry.pack(ipady=4); self.username_entry.focus()
        tk.Label(self, text="密碼:", font=FONT_NORMAL, bg=BG_COLOR, fg=TEXT_COLOR).pack(pady=(10,0))
        self.password_entry = tk.Entry(self, show="*", width=30, font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat")
        self.password_entry.pack(ipady=4); self.password_entry.bind("<Return>", self.handle_login)
        self.login_button = tk.Button(self, text="登入", font=FONT_NORMAL, bg=BUTTON_BG_COLOR, fg=TEXT_COLOR, activebackground=ACCENT_COLOR, activeforeground=BG_COLOR, relief="flat", padx=20, command=self.handle_login)
        self.login_button.pack(pady=20)

    def handle_login(self, event=None):
        username, password = self.username_entry.get(), self.password_entry.get()
        is_success, message, user_data = authenticate_ad_and_get_groups(username, password)
        if is_success:
            self.withdraw(); MainWindow(user_data=user_data, login_window=self)
        else: messagebox.showerror("登入失敗", message)

if __name__ == "__main__":
    logging.info("================ Application Started ================")
    app = LoginWindow()
    app.mainloop()


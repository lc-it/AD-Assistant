import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tkinter import filedialog # 【新增或確保這一行存在】
import webbrowser # 【新增】用於開啟下載連結
import mimetypes  # 【新增】用於辨識檔案類型
import ssl      # 【新增】明確引入 ssl 模組
import ssl
import requests
import json
import threading
import logging
from PIL import Image, ImageTk
from ldap3 import Server, Connection, ALL, Tls, SUBTREE
from packaging import version # 【新增】用於比較版本號

logging.basicConfig(filename='assistant.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', encoding='utf-8')

BG_COLOR, TEXT_COLOR, ACCENT_COLOR, ENTRY_BG_COLOR, BUTTON_BG_COLOR, BUTTON_HOVER_COLOR = "#282c34", "#abb2bf", "#61afef", "#1e2127", "#3a4049", "#4a515c"
FONT_NORMAL = ("Microsoft JhengHei", 10)
FONT_BOLD = ("Microsoft JhengHei", 12, "bold")
FONT_MONO = ("Consolas", 10)


# 全域設定

# 版本與更新設定
# 【新增】版本與更新設定
CURRENT_VERSION = "1.0.0"  # <<< 您目前開發中版本的版本號
UPDATE_INFO_URL = "https://raw.githubusercontent.com/lc-it/AD-Assistant/main/version.json" # <<< 版本資訊檔的路徑
APP_NAME = "MyAssistant.exe" # <<< 您最終產生的 EXE 檔名


ASSISTANT_WEBHOOKS = {
    "policy": "http://192.168.88.43:5678/webhook/OpenWebUIAdminAgent",
    "erp": "http://192.168.88.43:5678/webhook/ERPAgentWithFile", # 【修改】指向新的可處理檔案的 Webhook
   "meeting": "http://192.168.88.43:5678/webhook/MeetingAgentWithFile", # 【新增】會議助理 Webhook
   

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
        self.selected_files = {} # 【新增】用來儲存每個分頁選擇的檔案路徑
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
        # 【修改點】為每個助理新增 "welcome_message" 欄位
        ASSISTANT_MAPPING = {
            "G_Assistant_PolicyUsers": {
                "name": "行政助理", 
                "webhook_key": "policy",
                "welcome_message": "您好，我是行政助理，舉凡公司規章、表單申請或行政相關問題，都可以問我。"
            }, 
            "G_Assistant_ERPUsers": {
                "name": "ERP助理", 
                "webhook_key": "erp",
                "welcome_message": "您好！我是您的 ERP 助理，專門處理進銷存、料號或訂單相關問題，請問需要什麼協助嗎？"
            },
            "G_Assistant_MeetingUsers": {
                "name": "會議助理", 
                "webhook_key": "meeting",
                "welcome_message": "您好，我是會議助理。您可以上傳會議的錄音檔或逐字稿，我能為您產出會議記錄與待辦事項。"
            },

        }
        for group, info in ASSISTANT_MAPPING.items():
        #   if group in self.user_groups: # 您可以取消註解此行來啟用權限控管
                widgets = self.create_assistant_tab(info["name"], info["webhook_key"])
                # 【修改點】將歡迎詞也存入 tab_widgets_map 中
                tab_widgets_map[info["name"]] = {
                    "widgets": widgets, 
                    "webhook_key": info["webhook_key"],
                    "welcome_message": info.get("welcome_message", f"歡迎使用 {info['name']}！") # 使用 get 以防萬一漏寫
                }
        return tab_widgets_map
    
        for group, info in ASSISTANT_MAPPING.items():
            # if group in self.user_groups: # 您可以取消註解此行來啟用權限控管
                widgets = self.create_assistant_tab(info["name"], info["webhook_key"])
                tab_widgets_map[info["name"]] = {"widgets": widgets, "webhook_key": info["webhook_key"]}
        return tab_widgets_map

    def create_assistant_tab(self, name, webhook_key):
        frame = ttk.Frame(self.notebook, style="Custom.TFrame"); self.notebook.add(frame, text=name)
        frame.columnconfigure(0, weight=1)
        
        answer_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=FONT_MONO, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, relief="flat", insertbackground=TEXT_COLOR, spacing1=5, spacing3=5, padx=10, pady=5)
        answer_text.grid(row=0, column=0, columnspan=3, sticky="nsew", padx=10, pady=(0,5)); frame.rowconfigure(0, weight=1)
        
        answer_text.tag_configure("user_paragraph", justify="right")
        answer_text.tag_configure("assistant_paragraph", justify="left")
        answer_text.tag_configure("user_tag", foreground=ACCENT_COLOR, font=(FONT_MONO[0], FONT_MONO[1], 'bold'))
        answer_text.tag_configure("assistant_tag", foreground="#da70d6", font=(FONT_MONO[0], FONT_MONO[1], 'bold'))
        # 【新增】下載連結的樣式
        answer_text.tag_configure("download_link", foreground="#3399ff", underline=True)
        answer_text.tag_bind("download_link", "<Enter>", lambda e: answer_text.config(cursor="hand2"))
        answer_text.tag_bind("download_link", "<Leave>", lambda e: answer_text.config(cursor=""))
        answer_text.config(state="disabled")

        query_entry = tk.Entry(frame, font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief="flat")
        query_entry.grid(row=2, column=0, sticky="ew", padx=(10, 5), ipady=8)

        # 【新增】檔案上傳按鈕和狀態標籤
        upload_button = tk.Button(frame, text="上傳檔案", font=FONT_NORMAL, bg=BUTTON_BG_COLOR, fg=TEXT_COLOR, relief="flat",
                                  command=lambda: self.select_file(name))
        upload_button.grid(row=2, column=1, sticky="ew", padx=(0, 5), ipady=4)
        
        query_button = tk.Button(frame, text=" 發送", font=FONT_NORMAL, bg=BUTTON_BG_COLOR, fg=TEXT_COLOR, activebackground=ACCENT_COLOR, activeforeground=BG_COLOR, relief="flat", padx=10, compound="left", image=self.send_icon)
        query_button.grid(row=2, column=2, sticky="ew", padx=(0, 10), ipady=4)

        # 【新增】顯示已選檔案名稱的標籤
        file_status_label = tk.Label(frame, text="未選擇檔案", font=("Microsoft JhengHei", 8), bg=BG_COLOR, fg="grey")
        file_status_label.grid(row=1, column=0, columnspan=3, sticky="w", padx=12)

        status_label = tk.Label(frame, text="", font=("Microsoft JhengHei", 9), bg=BG_COLOR, fg=TEXT_COLOR)
        status_label.grid(row=3, column=0, columnspan=3, sticky="w", padx=10)

        def on_enter(e): e.widget['background'] = BUTTON_HOVER_COLOR
        def on_leave(e): e.widget['background'] = BUTTON_BG_COLOR
        query_button.bind("<Enter>", on_enter); query_button.bind("<Leave>", on_leave)
        upload_button.bind("<Enter>", on_enter); upload_button.bind("<Leave>", on_leave)

        command_func = lambda: self.start_assistant_query(query_entry, answer_text, query_button, status_label, webhook_key, name, upload_button, file_status_label)
        query_button.config(command=command_func); query_entry.bind("<Return>", lambda e: command_func())
        
        return {"query_entry": query_entry, "answer_text": answer_text, "query_button": query_button, 
                "status_label": status_label, "upload_button": upload_button, "file_status_label": file_status_label}

    # 【全新】選擇檔案的函式
    def select_file(self, tab_name):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        
        filename = filepath.split('/')[-1]
        self.selected_files[tab_name] = filepath # 儲存檔案路徑
        tab_info = self.tab_widgets.get(tab_name)
        if tab_info:
            # 更新UI顯示已選檔案
            tab_info["widgets"]["file_status_label"].config(text=f"已選檔案: {filename}", fg=ACCENT_COLOR)

    
    def on_tab_selected(self, event=None):
        if not self.notebook.tabs(): return
        selected_tab_name = self.notebook.tab(self.notebook.select(), "text")
        
        if selected_tab_name not in self.initialized_tabs:
            self.initialized_tabs.add(selected_tab_name)
            tab_info = self.tab_widgets.get(selected_tab_name)
            if tab_info:
                # 【修改點】從 tab_info 中讀取專屬歡迎詞，而不是產生通用句子
                # 我們也提供一個預設值，以防萬一找不到 welcome_message
                welcome_message = tab_info.get(
                    "welcome_message", 
                    f"您好！我是 {selected_tab_name}，請問有什麼可以為您服務的嗎？"
                )
                self.add_message_to_log(tab_info["widgets"]["answer_text"], selected_tab_name, welcome_message)

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

    def start_assistant_query(self, query_entry, answer_text, query_button, status_label, webhook_key, assistant_name, upload_button, file_status_label):
        query = query_entry.get().strip()
        filepath = self.selected_files.get(assistant_name)

        if not query and not filepath: # 如果文字和檔案都為空，則不執行
            messagebox.showwarning("提示", "請輸入問題或上傳檔案。")
            return
        
        self.add_message_to_log(answer_text, "You", query)
        query_entry.delete(0, tk.END)
        query_button.config(state="disabled"); query_entry.config(state="disabled"); upload_button.config(state="disabled")
        status_label.config(text="助理正在思考中...")
        
        webhook_url = ASSISTANT_WEBHOOKS.get(webhook_key)
        if not webhook_url or "YOUR_" in webhook_url:
            self.add_message_to_log(answer_text, assistant_name, "設定錯誤：Webhook URL 尚未設定！")
            query_button.config(state="normal"); query_entry.config(state="normal"); upload_button.config(state="normal"); status_label.config(text="")
            return

        logging.info(f"User '{self.username}' querying '{webhook_key}': '{query}' with file: {filepath}")
        
        # 啟動執行緒
        thread = threading.Thread(target=self.perform_assistant_query, 
                                  args=(query, webhook_url, answer_text, query_button, query_entry, 
                                        status_label, assistant_name, upload_button, file_status_label, filepath), 
                                  daemon=True)
        thread.start()

    def perform_assistant_query(self, query, webhook_url, answer_text, query_button, query_entry, status_label, assistant_name, upload_button, file_status_label, filepath):
        try:
            # ===================【偵錯起點】===================
            print("--- 開始執行 perform_assistant_query ---")
            print(f"Webhook URL: {webhook_url}")
            print(f"傳入的檔案路徑: {filepath}")

            if filepath:
                filename = filepath.split('/')[-1]
                content_type, _ = mimetypes.guess_type(filepath)
                
                print(f"從路徑解析出的檔名: {filename}")
                print(f"由 mimetypes 偵測到的 Content-Type: {content_type}") # <--- 這是最重要的檢查點！

                if content_type is None:
                    content_type = 'application/octet-stream'
                    print(f"Content-Type 為空，設定為預設值: {content_type}")

                with open(filepath, 'rb') as f:
                    files = {'file': (filename, f, content_type)}
                    payload = {'query': query}
                    
                    # 在發送前，再次印出準備好的資料
                    print(f"準備傳送的 payload (data): {payload}")
                    print(f"準備傳送的 files 結構: ('{filename}', file_object, '{content_type}')")
                    
                    response = requests.post(webhook_url, files=files, data=payload, timeout=180)

            else: # 如果沒有檔案
                print("沒有偵測到檔案，將作為純文字請求發送。")
                payload = {"query": query}
                headers = {'Content-Type': 'application/json'}
                response = requests.post(webhook_url, json=payload, headers=headers, timeout=50)
            
            print("--- 請求已發送，等待回應 ---")
            # ===================【偵錯終點】===================
            
            response.raise_for_status()
            response_data = response.json()
            answer = response_data.get("output", "n8n 回應中未找到 'output' 欄位。")
            download_url = response_data.get("download_url") 
            logging.info(f"Webhook call for '{assistant_name}' succeeded.")

        except Exception as e:
            answer, download_url = f"與後端服務溝通時發生錯誤。\n錯誤詳情: {e}", None
            logging.error(f"Webhook call for '{assistant_name}' failed: {e}", exc_info=True)
            print(f"發生錯誤: {e}") # 印出錯誤

        self.after(0, self.update_ui_after_query, answer, download_url, answer_text, query_button, query_entry, status_label, assistant_name, upload_button, file_status_label)


# --- 請用這個版本完整取代您舊的 update_ui_after_query 函式 ---

    def update_ui_after_query(self, answer, download_url, answer_text, query_button, query_entry, status_label, assistant_name, upload_button, file_status_label):
        status_label.config(text="")
        
        if self.selected_files.get(assistant_name):
            del self.selected_files[assistant_name]
            file_status_label.config(text="未選擇檔案", fg="grey")
        
        self.add_message_to_log(answer_text, assistant_name, answer, use_typewriter=True)

        if download_url:
            self.add_download_link(answer_text, download_url)

        query_button.config(state="normal")
        query_entry.config(state="normal")
        upload_button.config(state="normal")
        query_entry.focus()
        
    # 【全新】新增下載連結到對話框的函式
    def add_download_link(self, text_widget, url):
        text_widget.config(state="normal")
        text_widget.insert(tk.END, '\n') # 換行
        link_start_index = text_widget.index(tk.END)
        text_widget.insert(tk.END, "點此下載檔案", ("download_link",))
        
        # 為這個特定的連結片段綁定點擊事件
        text_widget.tag_bind("download_link", "<Button-1>", lambda e, u=url: webbrowser.open_new(u), add=True)
        
        end_index = text_widget.index(f"{tk.END}-1c")
        text_widget.tag_add("assistant_paragraph", link_start_index, end_index) # 保持靠左對齊
        text_widget.see(tk.END)
        text_widget.config(state="disabled")


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
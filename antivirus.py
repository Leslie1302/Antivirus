import sys
import json
import os
import shutil
import sqlite3
import threading
import queue
import logging
import time
import psutil
import winreg
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import messagebox
import tlsh  

# Check Python executable
print("Running with:", sys.executable)

# Configure logging
logging.basicConfig(
    filename='antivirus.log',
    level=logging.DEBUG,  # For more detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load malware signatures from JSON files in a directory
def load_malware_signatures(signatures_dir='signatures'):
    signatures = []
    signatures_dir = Path(signatures_dir)
    try:
        signatures_dir.mkdir(exist_ok=True)
        logging.debug(f"Signatures directory ensured: {signatures_dir}")
    except Exception as e:
        logging.error(f"Failed to create signatures directory {signatures_dir}: {e}")
        return signatures

    if not tlsh:
        logging.error("Cannot load signatures: TLSH library not available.")
        print("Error: TLSH library not available. Exiting.")
        return signatures

    json_files = list(signatures_dir.glob('*.json'))
    logging.debug(f"Found {len(json_files)} JSON files in {signatures_dir}")
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if 'tlsh' in data and 'name' in data:
                    signatures.append({
                        'tlsh': data['tlsh'],
                        'name': data['name'],
                        'size': data.get('size'),
                        'type': data.get('type')
                    })
                    logging.debug(f"Loaded signature from {json_file}: {data['name']}")
                else:
                    logging.warning(f"Skipping invalid JSON in {json_file}: missing 'tlsh' or 'name'")
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing JSON in {json_file}: {e}")
        except Exception as e:
            logging.error(f"Error reading {json_file}: {e}")
    logging.info(f"Loaded {len(signatures)} malware signatures from {signatures_dir}")
    print(f"Loaded {len(signatures)} malware signatures")
    return signatures

# Initialize quarantine database
def init_quarantine_db():
    try:
        conn = sqlite3.connect('quarantine.db', timeout=10)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS quarantine
                     (file_path TEXT, original_path TEXT, hash TEXT, reason TEXT, timestamp TEXT)''')
        conn.commit()
        conn.close()
        logging.debug("Quarantine database initialized")
    except Exception as e:
        logging.error(f"Failed to initialize quarantine database: {e}")

# Calculate TLSH hash with retry mechanism
def calculate_file_hash(file_path, max_retries=3, retry_delay=0.5):
    if not tlsh:
        logging.error(f"Cannot hash {file_path}: TLSH library not available.")
        return None
    file_path = Path(file_path)
    for attempt in range(max_retries):
        try:
            if not file_path.exists():
                logging.error(f"File not found: {file_path}")
                return None
            hash_obj = tlsh.Tlsh()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            hash_obj.final()
            hash_value = hash_obj.hexdigest() if hash_obj.is_valid() else None
            if hash_value:
                logging.debug(f"Calculated TLSH for {file_path}: {hash_value}")
            else:
                logging.warning(f"Invalid TLSH hash for {file_path}")
            return hash_value
        except (FileNotFoundError, PermissionError, OSError) as e:
            if attempt < max_retries - 1:
                logging.debug(f"Retry {attempt + 1}/{max_retries} for {file_path}: {e}")
                time.sleep(retry_delay)
                continue
            logging.error(f"Error hashing file {file_path} after {max_retries} attempts: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error hashing {file_path}: {e}")
            return None

# Quarantine file
def quarantine_file(file_path, reason):
    quarantine_dir = Path("quarantine")
    try:
        quarantine_dir.mkdir(exist_ok=True)
        logging.debug(f"Quarantine directory ensured: {quarantine_dir}")
    except Exception as e:
        logging.error(f"Failed to create quarantine directory: {e}")
        return False

    file_path = Path(file_path)
    if str(file_path).startswith(str(quarantine_dir)):
        logging.info(f"Skipping quarantine of file already in quarantine: {file_path}")
        return False

    dest_path = quarantine_dir / file_path.name
    try:
        file_hash = calculate_file_hash(file_path)
        shutil.move(file_path, dest_path)
        conn = sqlite3.connect('quarantine.db', timeout=10)
        c = conn.cursor()
        c.execute("INSERT INTO quarantine VALUES (?, ?, ?, ?, ?)",
                  (str(dest_path), str(file_path), file_hash, reason, time.ctime()))
        conn.commit()
        conn.close()
        logging.info(f"File quarantined: {file_path} -> {dest_path}")
        return True
    except (PermissionError, OSError) as e:
        logging.error(f"Failed to quarantine {file_path}: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error quarantining {file_path}: {e}")
        return False

# File system monitoring
class FileEventHandler(FileSystemEventHandler):
    def __init__(self, alert_queue, signatures):
        self.alert_queue = alert_queue
        self.signatures = signatures
        self.temp_extensions = {'.tmp', '.journal', '.temp', '~'}

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        if any(file_path.lower().endswith(ext) for ext in self.temp_extensions):
            logging.info(f"Skipping temporary file: {file_path}")
            return
        logging.info(f"New file detected: {file_path}")
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else None
        file_hash = calculate_file_hash(file_path)
        if not file_hash:
            return
        for sig in self.signatures:
            # Pre-filter by size (within 10% tolerance) and type (if available)
            if sig['size'] and file_size and abs(file_size - sig['size']) / sig['size'] > 0.1:
                continue
            if sig['type'] and sig['type'] == 'application/x-msdownload' and not file_path.lower().endswith('.exe'):
                continue
            # Compare TLSH hashes
            try:
                score = tlsh.diff(file_hash, sig['tlsh'])
                if score < 100:  # Similarity threshold
                    reason = f"Malware: {sig['name']} (TLSH score: {score})"
                    if quarantine_file(file_path, reason):
                        self.alert_queue.put(f"Malware detected and quarantined: {file_path} ({sig['name']})")
                        logging.info(f"Malware detected: {file_path} ({sig['name']}, score: {score})")
            except Exception as e:
                logging.error(f"Error comparing TLSH for {file_path} with {sig['name']}: {e}")

# Process monitoring
def monitor_processes(alert_queue):
    logging.info("Starting process monitoring...")
    while True:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                if proc.info['pid'] == 0 or proc.info['name'] in {'System', 'svchost.exe'}:  # Skip system processes
                    continue
                cpu_usage = proc.info['cpu_percent']
                if cpu_usage > 80.0:  # Lowered threshold for sensitivity
                    time.sleep(1)
                    cpu_usage = proc.cpu_percent(interval=1.0)
                    if cpu_usage > 80.0:
                        alert_queue.put(f"Suspicious process: {proc.info['name']} (PID: {proc.info['pid']}, CPU: {cpu_usage}%)")
                        logging.warning(f"Suspicious process: {proc.info['name']} (PID: {proc.info['pid']}, CPU: {cpu_usage}%)")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.debug(f"Process monitoring error: {e}")
        except Exception as e:
            logging.error(f"Unexpected error in process monitoring: {e}")
        time.sleep(5)

# Registry monitoring
def monitor_registry(alert_queue):
    logging.info("Starting registry monitoring...")
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    while True:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
            num_values = winreg.QueryInfoKey(key)[1]
            for i in range(num_values):
                name, value, _ = winreg.EnumValue(key, i)
                if "malware" in value.lower() or any(sus in value.lower() for sus in ['virus', 'trojan', 'worm']):  # Enhanced checks
                    alert_queue.put(f"Suspicious registry entry: {name} = {value}")
                    logging.warning(f"Suspicious registry entry: {name} = {value}")
            winreg.CloseKey(key)
        except WindowsError as e:
            logging.debug(f"Registry monitoring error: {e}")
        except Exception as e:
            logging.error(f"Unexpected error in registry monitoring: {e}")
        time.sleep(10)

# GUI for alerts
def run_gui(alert_queue):
    try:
        root = tk.Tk()
        root.title("Antivirus Alerts")
        root.geometry("400x300-50+50")
        text_area = tk.Text(root, height=15, width=50)
        text_area.pack(pady=10)

        def check_alerts():
            while not alert_queue.empty():
                alert = alert_queue.get()
                text_area.insert(tk.END, f"{alert}\n")
                text_area.see(tk.END)
                messagebox.showwarning("Antivirus Alert", alert)
            root.after(1000, check_alerts)

        check_alerts()
        root.mainloop()
    except Exception as e:
        logging.error(f"GUI error: {e}")
        print(f"GUI error: {e}")

def main():
    print("Starting antivirus...")
    logging.info("Starting antivirus...")
    init_quarantine_db()
    alert_queue = queue.Queue()
    signatures = load_malware_signatures('signatures')
    if not signatures:
        print("Error: No signatures loaded. Check antivirus.log for details.")
        logging.error("No signatures loaded. Exiting.")
        return
    print(f"Loaded {len(signatures)} signatures")
    logging.info(f"Loaded {len(signatures)} signatures")

    monitor_dir = Path.home() / "Documents"
    try:
        monitor_dir.mkdir(exist_ok=True)
        logging.info(f"Monitoring directory ensured: {monitor_dir}")
    except Exception as e:
        print(f"Failed to create monitoring directory {monitor_dir}: {e}")
        logging.error(f"Failed to create monitoring directory {monitor_dir}: {e}")
        return

    observer = Observer()
    event_handler = FileEventHandler(alert_queue, signatures)
    try:
        observer.schedule(event_handler, str(monitor_dir), recursive=True)
        observer.start()
        logging.info(f"Started file system monitoring for {monitor_dir}")
        print(f"Started file system monitoring for {monitor_dir}")
    except Exception as e:
        print(f"Failed to start file system monitoring: {e}")
        logging.error(f"Failed to start file system monitoring: {e}")
        return

    process_thread = threading.Thread(target=monitor_processes, args=(alert_queue,), daemon=True)
    process_thread.start()

    registry_thread = threading.Thread(target=monitor_registry, args=(alert_queue,), daemon=True)
    registry_thread.start()

    gui_thread = threading.Thread(target=run_gui, args=(alert_queue,), daemon=True)
    gui_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("Antivirus stopped by user.")
        logging.info("Antivirus stopped by user.")
    finally:
        observer.join()

if __name__ == "__main__":
    main()
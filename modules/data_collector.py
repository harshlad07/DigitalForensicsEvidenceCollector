import os
import psutil, time, winreg
import platform
import subprocess
import socket


def find_process_by_name_or_pid(identifier):
    try:
        pid = int(identifier)
        proc = psutil.Process(pid)
        return proc
    except ValueError:
        # Treat as name
        for proc in psutil.process_iter(['pid', 'name']):
            if identifier.lower() in proc.info['name'].lower():
                return proc
    except psutil.NoSuchProcess:
        return None
    return None

# Collecting live process logs
def get_process_details(proc):
    try:
        return {
            "pid": proc.pid,
            "name": proc.name(),
            "exe": proc.exe(),
            "cmdline": proc.cmdline(),
            "start_time": proc.create_time(),
            "cpu_percent": proc.cpu_percent(interval=1),
            "memory_info": proc.memory_info()._asdict(),
            "open_files": [f.path for f in proc.open_files()],
            "connections": [conn._asdict() for conn in proc.connections() if conn.raddr],
            "children": [child.pid for child in proc.children()]
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return {"error": f"{type(e).__name__}: {e}"}

# Collecting logs for a specific software/application
def monitor_process_live(proc, duration=10):
    usage_log = []
    for _ in range(duration):
        try:
            usage_log.append({
                "cpu_percent": proc.cpu_percent(interval=1),
                "memory_info": proc.memory_info()._asdict(),
                "timestamp": time.time()
            })
        except psutil.NoSuchProcess:
            break
    return usage_log

# Collecting PIDs
def get_logs_for_pid(pid):
    logs = []
    if platform.system() == "Linux":
        try:
            result = subprocess.run(
                ["journalctl", f"_PID={pid}", "--since", "today", "--output=short"],
                capture_output=True, text=True
            )
            logs = result.stdout.strip().splitlines()
        except Exception as e:
            logs = [f"Log collection failed: {e}"]
    elif platform.system() == "Windows":
        try:
            cmd = f'wevtutil qe System /q:"*[System[Execution[@ProcessID={pid}]]]" /f:text /c:10'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            logs = result.stdout.strip().splitlines()
        except Exception as e:
            logs = [f"Log collection failed: {e}"]
    else:
        logs = ["Log collection not supported on this OS."]
    return logs

# Collecting USB logs
def get_usb_history():
    if platform.system() == "Windows":
        try:
            import wmi
            c = wmi.WMI()
            usb_devices = [d.PNPDeviceID for d in c.Win32_DiskDrive() if "USB" in d.PNPDeviceID]
            return usb_devices
        except ImportError:
            return ["pywin32 not installed or WMI import failed."]
    elif platform.system() == "Linux":
        try:
            result = subprocess.run(["lsusb"], capture_output=True, text=True)
            return result.stdout.strip().split('\n')
        except Exception as e:
            return [str(e)]
    else:
        return ["Unsupported OS for USB history"]

# Collecting recent files logs
def get_recent_files():
    recent_files = []
    if platform.system() == "Windows":
        recent_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent')
        if os.path.exists(recent_path):
            for entry in os.listdir(recent_path):
                full_path = os.path.join(recent_path, entry)
                if os.path.isfile(full_path):
                    recent_files.append(full_path)
    elif platform.system() == "Linux":
        try:
            result = subprocess.run(
                ["find", "/home", "-type", "f", "-printf", "%T@ %p\n"],
                capture_output=True, text=True
            )
            files = sorted(result.stdout.splitlines(), reverse=True)
            recent_files = [line.split(" ", 1)[1] for line in files[:10]]  # latest 10
        except Exception as e:
            recent_files.append(str(e))
    else:
        recent_files.append("Unsupported OS for recent file history")
    return recent_files

# Collecting running processes
def collect_running_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            info = proc.info
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes

# Collect open network connections 
def collect_network_connections():
    connections = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr:
            ip = conn.raddr.ip
            try:
                domain = socket.gethostbyaddr(ip)[0]
            except Exception:
                domain = None
            connections.append({
                "pid": conn.pid,
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_address": f"{ip}:{conn.raddr.port}",
                "domain": domain,
                "status": conn.status
            })
    return connections

# Collecting System information
def collect_system_info():
    return {
        "platform": platform.system(),
        "platform-release": platform.release(),
        "platform-version": platform.version(),
        "arch": platform.machine(),
        "hostname": platform.node(),
        "processor": platform.processor(),
        "architecture": platform.architecture(),
    }


def snapshot_registry_keys(base_key, subkey=""):
    keys = {}
    try:
        with winreg.OpenKey(base_key, subkey) as handle:
            for i in range(winreg.QueryInfoKey(handle)[0]):
                try:
                    sub_k = winreg.EnumKey(handle, i)
                    full_subkey = f"{subkey}\\{sub_k}" if subkey else sub_k
                    keys[full_subkey] = snapshot_registry_keys(base_key, full_subkey)
                except Exception:
                    continue
            for j in range(winreg.QueryInfoKey(handle)[1]):
                try:
                    value_name, value_data, value_type = winreg.EnumValue(handle, j)
                    keys.setdefault(subkey, {})[value_name] = str(value_data)
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    return keys

def collect_registry_snapshot():
    snapshot = {}
    root_keys = {
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    }
    for name, hkey in root_keys.items():
        snapshot[name] = snapshot_registry_keys(hkey)
    return snapshot

def compare_registry_snapshots(old, new):
    added, removed, modified = {}, {}, {}

    def deep_diff(o, n, path=""):
        if isinstance(o, dict) and isinstance(n, dict):
            for key in n.keys() - o.keys():
                added[path + "\\" + key] = n[key]
            for key in o.keys() - n.keys():
                removed[path + "\\" + key] = o[key]
            for key in o.keys() & n.keys():
                deep_diff(o[key], n[key], path + "\\" + key)
        else:
            if o != n:
                modified[path] = {"from": o, "to": n}

    deep_diff(old, new)
    return {"added": added, "removed": removed, "modified": modified}
"""
system_monitor.py

Advanced Windows system diagnostics, real-time monitoring and professional audit report generator.

Usage:
  python system_monitor.py
  python system_monitor.py --once
  python system_monitor.py --export json
  python system_monitor.py --export html
  python system_monitor.py --export csv
  python system_monitor.py --export pdf

Dependencies are installed automatically if missing.
"""
from __future__ import annotations

import argparse
import csv
import datetime
import importlib
import json
import math
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
import winreg
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

REQUIRED_PACKAGES = { "psutil": "psutil",  "cpuinfo": "py-cpuinfo", "GPUtil": "GPUtil", "wmi": "WMI", "rich": "rich", "tabulate": "tabulate", "requests": "requests", "fpdf": "fpdf"}


def ensure_package(name: str, package: str):
    try:
        return importlib.import_module(name)
    except ImportError:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            return importlib.import_module(name)
        except Exception:
            return None


psutil = ensure_package("psutil", REQUIRED_PACKAGES["psutil"])
cpuinfo = ensure_package("cpuinfo", REQUIRED_PACKAGES["cpuinfo"])
GPUtil = ensure_package("GPUtil", REQUIRED_PACKAGES["GPUtil"])
wmi = ensure_package("wmi", REQUIRED_PACKAGES["wmi"])
requests = ensure_package("requests", REQUIRED_PACKAGES["requests"])
fpdf = ensure_package("fpdf", REQUIRED_PACKAGES["fpdf"])
rich_module = ensure_package("rich", REQUIRED_PACKAGES["rich"])
ensure_package("tabulate", REQUIRED_PACKAGES["tabulate"])

if rich_module is None:
    print
    raise SystemExit("Required package 'rich' could not be installed. Please run: python -m pip install rich")

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import BarColumn, Progress, TextColumn

console = Console()


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def safe_call(func, default=None, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception:
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def human_bytes(value: Optional[float]) -> str:
    if value is None:
        return "-"
    try:
        number = float(value)
    except Exception:
        return "-"
    for unit in ["", "K", "M", "G", "T", "P"]:
        if abs(number) < 1024.0:
            return f"{number:3.1f}{unit}B"
        number /= 1024.0
    return f"{number:.1f}YB"


def human_time(seconds: float) -> str:
    try:
        seconds = int(seconds)
    except Exception:
        return "-"
    return str(datetime.timedelta(seconds=seconds))


def percent_bar(value: float, width: int = 28) -> str:
    value = max(0.0, min(100.0, value))
    filled = int((value / 100.0) * width)
    return "█" * filled + "─" * (width - filled)


def ascii_sparkline(data: List[float], width: int = 28) -> str:
    blocks = "▁▂▃▄▅▆▇█"
    if not data:
        return "".ljust(width)
    if len(data) > width:
        step = len(data) / width
        sampled = [data[int(i * step)] for i in range(width)]
    else:
        sampled = data + [data[-1]] * (width - len(data))
    mn, mx = min(sampled), max(sampled)
    if mx == mn:
        return blocks[0] * width
    spark = ""
    for value in sampled[:width]:
        idx = int((value - mn) / (mx - mn) * (len(blocks) - 1))
        spark += blocks[idx]
    return spark


def run_command(command: List[str], timeout: int = 12) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except Exception:
        return ""


def run_powershell(script: str) -> Optional[Any]:
    if not is_windows():
        return None
    output = run_command(["powershell", "-NoProfile", "-Command", script])
    if not output:
        return None
    try:
        return json.loads(output)
    except Exception:
        return output


def get_public_ip() -> str:
    if requests is None:
        return "-"
    for endpoint in ["https://ifconfig.me/ip", "https://api.ipify.org"]:
        try:
            response = requests.get(endpoint, timeout=5)
            if response.ok:
                return response.text.strip()
        except Exception:
            continue
    return "-"


def geo_lookup(ip: str) -> Dict[str, str]:
    if requests is None or ip in {"-", "127.0.0.1", "::1"}:
        return {"country": "-", "region": "-", "city": "-"}
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=6)
        if response.ok:
            data = response.json()
            return {"country": data.get("country_name", "-"), "region": data.get("region", "-"), "city": data.get("city", "-")}
    except Exception:
        pass
    return {"country": "-", "region": "-", "city": "-"}


def detect_virtualization() -> List[str]:
    markers: List[str] = []
    machine_info = " ".join(filter(None, [platform.platform(), platform.uname().system, platform.uname().node, platform.uname().release, platform.uname().version, platform.uname().machine, platform.uname().processor])).lower()
    tumors = {
        "vmware": "VMware",
        "virtualbox": "VirtualBox",
        "kvm": "KVM",
        "hyper-v": "Hyper-V",
        "hyperv": "Hyper-V",
        "xen": "Xen",
        "qemu": "QEMU",
    }
    for key, label in tumors.items():
        if key in machine_info:
            markers.append(label)
    if wmi is not None:
        try:
            computer = wmi.WMI().Win32_ComputerSystem()[0]
            manufacturer = getattr(computer, "Manufacturer", "").lower()
            model = getattr(computer, "Model", "").lower()
            for key, label in tumors.items():
                if key in manufacturer or key in model:
                    if label not in markers:
                        markers.append(label)
        except Exception:
            pass
    return markers or ["Physical"]


class SystemInfoCollector:

    def __init__(self) -> None:
        self._wmi = wmi.WMI() if wmi is not None else None

    def collect(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "hostname": socket.gethostname(),
            "user": os.environ.get("USERNAME", os.environ.get("USER", "-")),
            "os_name": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "datetime": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "uptime": "-",
            "bios_version": "-",
            "bios_serial": "-",
            "manufacturer": "-",
            "model": "-",
        }
        if psutil is not None:
            try:
                boot = datetime.datetime.fromtimestamp(psutil.boot_time())
                info["uptime"] = str(datetime.datetime.now() - boot).split(".")[0]
            except Exception:
                pass
        if self._wmi is not None:
            try:
                bios = self._wmi.Win32_BIOS()[0]
                system = self._wmi.Win32_ComputerSystem()[0]
                info["bios_version"] = getattr(bios, "SMBIOSBIOSVersion", "-")
                info["bios_serial"] = getattr(bios, "SerialNumber", "-")
                info["manufacturer"] = getattr(system, "Manufacturer", "-")
                info["model"] = getattr(system, "Model", "-")
            except Exception:
                pass
        return info


class CPUCollector:

    def __init__(self, history_len: int = 120) -> None:
        self.history: deque[float] = deque(maxlen=history_len)

    def collect_specs(self) -> Dict[str, Any]:
        specs: Dict[str, Any] = {"name": "-", "vendor": "-", "physical_cores": 0, "logical_cores": 0, "min_freq": None, "max_freq": None, "current_freq": None}
        if cpuinfo is not None:
            try:
                info = cpuinfo.get_cpu_info()
                specs["name"] = info.get("brand_raw", platform.processor() or "-")
                specs["vendor"] = info.get("vendor_id_raw", "-")
            except Exception:
                specs["name"] = platform.processor() or "-"
        else:
            specs["name"] = platform.processor() or "-"
        if psutil is not None:
            specs["physical_cores"] = safe_int(psutil.cpu_count(logical=False))
            specs["logical_cores"] = safe_int(psutil.cpu_count(logical=True))
            freqs = safe_call(psutil.cpu_freq, default=None)
            specs["min_freq"] = getattr(freqs, "min", None)
            specs["max_freq"] = getattr(freqs, "max", None)
            specs["current_freq"] = getattr(freqs, "current", None)
        return specs

    def collect_metrics(self) -> Dict[str, Any]:
        if psutil is None:
            return {"overall": 0.0, "per_core": [], "loadavg": (0.0, 0.0, 0.0), "history": list(self.history)}
        overall = safe_call(psutil.cpu_percent, default=0.0, interval=None)
        per_core = safe_call(psutil.cpu_percent, default=[], interval=None, percpu=True)
        self.history.append(overall)
        loadavg = safe_call(os.getloadavg, default=(0.0, 0.0, 0.0)) if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
        return {"overall": overall, "per_core": per_core, "loadavg": loadavg, "history": list(self.history)}


class MemoryCollector:

    def collect(self) -> Dict[str, Any]:
        if psutil is None:
            return {}
        vm = safe_call(psutil.virtual_memory, default=None)
        sm = safe_call(psutil.swap_memory, default=None)
        if vm is None or sm is None:
            return {}
        return {
            "total": vm.total,
            "used": vm.used,
            "free": vm.free,
            "available": vm.available,
            "percent": vm.percent,
            "swap_total": sm.total,
            "swap_used": sm.used,
            "swap_free": sm.free,
            "swap_percent": sm.percent,
        }


class DiskCollector:

    def __init__(self) -> None:
        self._wmi = wmi.WMI() if wmi is not None else None

    def collect_partitions(self) -> List[Dict[str, Any]]:
        partitions: List[Dict[str, Any]] = []
        if psutil is None:
            return partitions
        for part in safe_call(psutil.disk_partitions, default=[], all=False):
            try:
                usage = safe_call(psutil.disk_usage, default=None, path=part.mountpoint)
            except Exception:
                usage = None
            partitions.append({
                "mountpoint": part.mountpoint,
                "device": part.device,
                "fstype": part.fstype,
                "usage": usage,
            })
        return partitions

    def collect_io(self) -> Dict[str, Any]:
        if psutil is None:
            return {}
        io = safe_call(psutil.disk_io_counters, default=None, perdisk=False)
        return io._asdict() if io else {}

    def collect_smart(self) -> List[Dict[str, Any]]:
        diagnostics: List[Dict[str, Any]] = []
        if self._wmi is None:
            return diagnostics
        try:
            for disk in self._wmi.Win32_DiskDrive():
                diagnostics.append({
                    "device": getattr(disk, "DeviceID", "-"),
                    "model": getattr(disk, "Model", "-"),
                    "status": getattr(disk, "Status", "Unknown"),
                })
        except Exception:
            pass
        return diagnostics


        # le programme is runing dans une interface logique et capable de renitalisation les dependices et les arguments 
        # contre  les arguments d'exportation et de generation de rapport et de diagnostic
        # le programme est capable de faire un rapport en temps réel et de faire une analyse de diagnostic et de faire un rapport d'audit complet et détaillé avec des recommandations et des explications et des graphiques et des tableaux et des scores et des grades et des comparaisons avec d'autres systèmes similaires et de faire une exportation en json csv html pdf et de faire une interface graphique avec rich pour afficher les données en temps réel et de faire une analyse de sécurité pour détecter les vuln
        # si le programme va runing dans une interface logique et capable de renitailisation des dependices et des arguments d'exportation et de generation de rapport et de diagnostic alors le programme va faire un rapport en temps réel et de faire une analyse de diagnostic et de faire un rapport d'audit complet et détaillé avec des recommandations et des explications et des graphiques et des tableaux et des scores et des grades et des comparaisons avec d'autres systèmes similaires et de faire une exportation en json csv html pdf et de faire une interface graphique avec rich pour afficher les données en temps réel et de faire une analyse de sécurité pour détecter les vulnérabilités potentielles et les risques pour la sécurité du système



class NetworkCollector:

    def __init__(self) -> None:
        self._last_io = safe_call(psutil.net_io_counters, default=None, pernic=False)
        self._last_time = time.time()

    def collect_interfaces(self) -> List[Dict[str, Any]]:
        interfaces: List[Dict[str, Any]] = []
        if psutil is None:
            return interfaces
        addrs = safe_call(psutil.net_if_addrs, default={}) or {}
        stats = safe_call(psutil.net_if_stats, default={}) or {}
        for name, addr_list in addrs.items():
            ipv4 = "-"
            ipv6 = "-"
            mac = "-"
            for addr in addr_list:
                family = getattr(addr, "family", None)
                if family == socket.AF_INET:
                    ipv4 = getattr(addr, "address", "-")
                elif family == socket.AF_INET6:
                    ipv6 = getattr(addr, "address", "-")
                elif family == getattr(psutil, "AF_LINK", 17):
                    mac = getattr(addr, "address", "-")
            stat = stats.get(name)
            interfaces.append({
                "name": name,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "mac": mac,
                "is_up": getattr(stat, "isup", False) if stat else False,
                "speed": getattr(stat, "speed", 0) if stat else 0,
            })
        return interfaces

    def collect_throughput(self) -> Dict[str, float]:
        if psutil is None:
            return {"sent_rate": 0.0, "recv_rate": 0.0}
        current = safe_call(psutil.net_io_counters, default=None, pernic=False)
        if current is None or self._last_io is None:
            self._last_io = current
            self._last_time = time.time()
            return {"sent_rate": 0.0, "recv_rate": 0.0}
        now = time.time()
        elapsed = max(now - self._last_time, 0.001)
        rates = {
            "sent_rate": (current.bytes_sent - self._last_io.bytes_sent) / elapsed,
            "recv_rate": (current.bytes_recv - self._last_io.bytes_recv) / elapsed,
        }
        self._last_io = current
        self._last_time = now
        return rates


class GPUCollector:

    def collect(self) -> List[Dict[str, Any]]:
        gpus: List[Dict[str, Any]] = []
        if GPUtil is None:
            return gpus
        try:
            for gpu in GPUtil.getGPUs():
                gpus.append({
                    "name": gpu.name,
                    "driver": getattr(gpu, "driver", "-"),
                    "memory_total": getattr(gpu, "memoryTotal", 0),
                    "memory_used": getattr(gpu, "memoryUsed", 0),
                    "load": getattr(gpu, "load", 0) * 100,
                    "temperature": getattr(gpu, "temperature", None),
                })
        except Exception:
            pass
        return gpus


class SensorCollector:

    def collect(self) -> Dict[str, Any]:
        sensors: Dict[str, Any] = {"temperatures": {}, "fans": {}, "wmi": []}
        if psutil is not None:
            if hasattr(psutil, "sensors_temperatures"):
                sensors["temperatures"] = safe_call(psutil.sensors_temperatures, default={}) or {}
            if hasattr(psutil, "sensors_fans"):
                sensors["fans"] = safe_call(psutil.sensors_fans, default={}) or {}
        if wmi is not None:
            try:
                w = wmi.WMI()
                for zone in getattr(w, "MSAcpi_ThermalZoneTemperature", [])():
                    current = getattr(zone, "CurrentTemperature", None)
                    if current is not None:
                        sensors["wmi"].append({
                            "name": getattr(zone, "InstanceName", "unknown"),
                            "current": current / 10.0 - 273.15,
                        })
            except Exception:
                pass
        return sensors


class ProcessCollector:

    def collect_top_cpu(self, limit: int = 20) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if psutil is None:
            return results
        for proc in safe_call(psutil.process_iter, default=[], attrs=["pid", "name", "cpu_percent", "memory_info", "status"]):
            try:
                info = proc.info
                results.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "cpu": info.get("cpu_percent", 0.0),
                    "memory": getattr(info.get("memory_info"), "rss", 0) if info.get("memory_info") else 0,
                    "status": info.get("status"),
                })
            except Exception:
                continue
        return sorted(results, key=lambda item: item["cpu"], reverse=True)[:limit]

    def collect_top_memory(self, limit: int = 20) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if psutil is None:
            return results
        for proc in safe_call(psutil.process_iter, default=[], attrs=["pid", "name", "cpu_percent", "memory_info", "status"]):
            try:
                info = proc.info
                results.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "cpu": info.get("cpu_percent", 0.0),
                    "memory": getattr(info.get("memory_info"), "rss", 0) if info.get("memory_info") else 0,
                    "status": info.get("status"),
                })
            except Exception:
                continue
        return sorted(results, key=lambda item: item["memory"], reverse=True)[:limit]


class ServiceCollector:

    def collect(self) -> List[Dict[str, Any]]:
        services: List[Dict[str, Any]] = []
        if wmi is None:
            return services
        try:
            client = wmi.WMI()
            for service in getattr(client, "Win32_Service", [])():
                services.append({
                    "name": getattr(service, "Name", "-"),
                    "display_name": getattr(service, "DisplayName", "-"),
                    "state": getattr(service, "State", "-"),
                    "start_mode": getattr(service, "StartMode", "-"),
                })
        except Exception:
            pass
        return services


class SecurityCollector:

    def _defender_status(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"enabled": False, "realtime": False, "antivirus": False, "antispyware": False, "status": "Unknown"}
        if not is_windows():
            return data
        script = "Try { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,ThreatProtectionEnabled | ConvertTo-Json -Compress } Catch { Write-Output '{}' }"
        raw = run_powershell(script)
        if isinstance(raw, dict) and raw:
            data["enabled"] = raw.get("AMServiceEnabled", False)
            data["antivirus"] = raw.get("AntivirusEnabled", False)
            data["antispyware"] = raw.get("AntispywareEnabled", False)
            data["realtime"] = raw.get("RealTimeProtectionEnabled", False)
            data["status"] = "Protected" if data["enabled"] else "Disabled"
        return data

    def _firewall_status(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"enabled": False, "profiles": []}
        if not is_windows():
            return data
        script = "Try { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress } Catch { Write-Output '{}' }"
        raw = run_powershell(script)
        if isinstance(raw, list):
            for item in raw:
                data["profiles"].append({
                    "name": item.get("Name", "-"),
                    "enabled": item.get("Enabled", False),
                    "inbound": item.get("DefaultInboundAction", "-"),
                    "outbound": item.get("DefaultOutboundAction", "-"),
                })
            data["enabled"] = any(profile["enabled"] for profile in data["profiles"])
        return data

    def _antivirus_products(self) -> List[Dict[str, Any]]:
        products: List[Dict[str, Any]] = []
        if not is_windows():
            return products
        script = "Try { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName,pathToSignedProductExe,productState | ConvertTo-Json -Compress } Catch { Write-Output '{}' }"
        raw = run_powershell(script)
        if isinstance(raw, dict):
            raw = [raw]
        if isinstance(raw, list):
            for item in raw:
                products.append({
                    "name": item.get("displayName", "-"),
                    "path": item.get("pathToSignedProductExe", "-"),
                    "raw_state": item.get("productState", "-"),
                })
        return products

    def collect(self) -> Dict[str, Any]:
        defender = self._defender_status()
        firewall = self._firewall_status()
        antivirus = self._antivirus_products()
        score = 0
        score += 30 if defender.get("enabled") else 0
        score += 30 if defender.get("realtime") else 0
        score += 20 if firewall.get("enabled") else 0
        score += 20 if bool(antivirus) else 0
        status = "Secure" if score >= 80 else "Attention" if score >= 50 else "Risk"
        return {
            "defender": defender,
            "firewall": firewall,
            "antivirus": antivirus,
            "security_score": min(100, score),
            "status": status,
        }


class PortCollector:

    def collect(self, limit: int = 20) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        if psutil is None:
            return items
        for conn in safe_call(psutil.net_connections, default=[], kind="inet"):
            try:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                items.append({
                    "proto": "UDP" if conn.type == socket.SOCK_DGRAM else "TCP",
                    "status": conn.status,
                    "local": laddr,
                    "remote": raddr,
                    "pid": conn.pid,
                })
            except Exception:
                continue
        return sorted(items, key=lambda x: x["local"])[:limit]


class InstalledProgramsCollector:

    UNINSTALL_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    def collect(self) -> List[Dict[str, Any]]:
        programs: List[Dict[str, Any]] = []
        if not is_windows():
            return programs
        for hive, path in self.UNINSTALL_KEYS:
            try:
                key = winreg.OpenKey(hive, path)
            except Exception:
                continue
            count = safe_call(winreg.QueryInfoKey, (0, 0, 0), key)[0]
            for index in range(count):
                try:
                    subkey_name = winreg.EnumKey(key, index)
                    subkey = winreg.OpenKey(key, subkey_name)
                    name = safe_call(winreg.QueryValueEx, (None, None), subkey, "DisplayName")[0]
                    if not name:
                        continue
                    version = safe_call(winreg.QueryValueEx, (None, None), subkey, "DisplayVersion")[0]
                    publisher = safe_call(winreg.QueryValueEx, (None, None), subkey, "Publisher")[0]
                    install_date = safe_call(winreg.QueryValueEx, (None, None), subkey, "InstallDate")[0]
                    programs.append({
                        "name": name,
                        "version": version or "-",
                        "publisher": publisher or "-",
                        "install_date": install_date or "-",
                    })
                except Exception:
                    print(f"Warning: Failed to read registry entry at {hive}\\{path}\\{subkey_name}", file=sys.stderr)
                    print(f"Exception: {sys.exc_info()[0]} - {sys.exc_info()[1]}", file=sys.stderr)
                    continue
        return sorted(programs, key=lambda item: item.get("name", ""))[:120]


class ActiveConnectionCollector:

    def collect(self, limit: int = 20) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        if psutil is None:
            return items
        geo_cache: Dict[str, Dict[str, str]] = {}
        for conn in safe_call(psutil.net_connections, default=[], kind="inet"):
            if not conn.raddr:
                continue
            remote_ip = conn.raddr.ip
            if remote_ip not in geo_cache:
                geo_cache[remote_ip] = geo_lookup(remote_ip)
            geo = geo_cache[remote_ip]
            items.append({
                "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-",
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                "pid": conn.pid,
                "status": conn.status,
                "country": geo.get("country", "-"),
            })
        return sorted(items, key=lambda x: x["remote"])[:limit]


class BenchmarkEngine:

    def collect(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        data["cpu_time"] = self._cpu_test()
        data["ram_time"] = self._ram_test()
        data["disk_time"] = self._disk_test()
        data["cpu_score"] = self._score_from_time(data["cpu_time"], 1.5, 4.0)
        data["ram_score"] = self._score_from_time(data["ram_time"], 0.8, 3.0)
        data["disk_score"] = self._score_from_time(data["disk_time"], 0.5, 2.5)
        return data

    def _cpu_test(self) -> float:
        start = time.perf_counter()
        total = 0.0
        for value in range(1, 1500000):
            total += math.sqrt(value)
        return time.perf_counter() - start

    def _ram_test(self) -> float:
        start = time.perf_counter()
        block = [i for i in range(500000)]
        total = sum(block)
        del block
        return time.perf_counter() - start

    def _disk_test(self) -> float:
        start = time.perf_counter()
        try:
            with tempfile.NamedTemporaryFile(delete=False) as handle:
                handle.write(os.urandom(4 * 1024 * 1024))
                path = handle.name
            with open(path, "rb") as handle:
                handle.read()
        except Exception:
            return 5.0
        finally:
            try:
                os.remove(path)
            except Exception:
                pass
        return time.perf_counter() - start

    def _score_from_time(self, value: float, best: float, worst: float) -> int:
        if value <= best:
            return 100
        if value >= worst:
            return 20
        return int(100 - ((value - best) / (worst - best)) * 80)


class DiagnosticEngine:

    def evaluate(self, cpu_pct: float, ram_pct: float, partitions: List[Dict[str, Any]], sensors: Dict[str, Any], security_score: int) -> Dict[str, Any]:
        issues: List[str] = []
        recommendations: List[str] = []
        score = 100

        if cpu_pct >= 90:
            issues.append("CPU usage critically high")
            recommendations.append("Investigate top CPU processes and reduce workload")
            score -= 25
        elif cpu_pct >= 75:
            issues.append("CPU usage elevated")
            score -= 10

        if ram_pct >= 95:
            issues.append("RAM critically high")
            recommendations.append("Close or optimize memory-heavy applications")
            score -= 25
        elif ram_pct >= 80:
            issues.append("RAM usage elevated")
            score -= 10

        for part in partitions:
            usage = part.get("usage")
            if usage is None:
                continue
            percent = getattr(usage, "percent", 0)
            if percent >= 95:
                issues.append(f"Disk {part.get('mountpoint')} critically full ({percent:.1f}%)")
                recommendations.append("Free disk space from critical partitions")
                score -= 25
            elif percent >= 85:
                issues.append(f"Disk {part.get('mountpoint')} nearly full ({percent:.1f}%)")
                score -= 10

        temps: List[float] = []
        for temp_list in sensors.get("temperatures", {}).values():
            for entry in temp_list:
                current = getattr(entry, "current", None)
                if current is not None:
                    temps.append(float(current))
        for item in sensors.get("wmi", []):
            current = item.get("current")
            if current is not None:
                temps.append(float(current))

        for temp in temps:
            if temp >= 90:
                issues.append("Temperature critical")
                recommendations.append("Inspect cooling and fan operation")
                score -= 20
            elif temp >= 80:
                issues.append("Temperature elevated")
                score -= 10

        score = max(0, score)
        raw_status = "Healthy" if score >= 70 else "Attention" if score >= 40 else "Critical"
        if security_score < 60:
            raw_status = "Security Concern"
            score -= 10
        grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D"
        status = f"{raw_status} ({grade})"

        explanation = "No critical anomalies detected" if not issues else "; ".join(issues)
        return {"status": status, "explanation": explanation, "recommendations": recommendations, "score": score, "grade": grade}


class ReportGenerator:

    def __init__(self) -> None:
        self.output_directory = Path.cwd()

    def export_json(self, filename: str, data: Dict[str, Any]) -> str:
        path = self.output_directory / filename
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        return str(path)

    def export_csv(self, filename: str, data: Dict[str, Any]) -> str:
        path = self.output_directory / filename
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Section", "Key", "Value"])
            for section, section_data in data.items():
                if isinstance(section_data, dict):
                    for key, value in section_data.items():
                        writer.writerow([section, key, json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value])
                else:
                    writer.writerow([section, "value", json.dumps(section_data, ensure_ascii=False) if isinstance(section_data, (dict, list)) else section_data])
        return str(path)

    def export_html(self, filename: str, data: Dict[str, Any]) -> str:
        path = self.output_directory / filename
        html_lines = [
            "<html><head><meta charset='utf-8'><title>System Audit Report</title><style>body{font-family:Arial,Helvetica,sans-serif;background:#121212;color:#f0f0f0;}table{width:100%;border-collapse:collapse;margin-bottom:1rem;}th,td{border:1px solid #444;padding:0.5rem;text-align:left;}th{background:#1f1f1f;}section{margin-bottom:1.4rem;}h1,h2{color:#9cd4ff;}</style></head><body>",
            "<h1>System Audit Report</h1>",
            f"<p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        ]
        for section, section_data in data.items():
            html_lines.append(f"<section><h2>{section}</h2>")
            if isinstance(section_data, dict):
                html_lines.append("<table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>")
                for key, value in section_data.items():
                    html_lines.append(f"<tr><td>{key}</td><td>{json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value}</td></tr>")
                html_lines.append("</tbody></table>")
            elif isinstance(section_data, list):
                if section_data and isinstance(section_data[0], dict):
                    keys = sorted({key for item in section_data for key in item.keys()})
                    html_lines.append("<table><thead><tr>" + "".join(f"<th>{key}</th>" for key in keys) + "</tr></thead><tbody>")
                    for item in section_data:
                        html_lines.append("<tr>" + "".join(f"<td>{json.dumps(item.get(key, ''), ensure_ascii=False) if isinstance(item.get(key, ''), (dict, list)) else item.get(key, '')}</td>" for key in keys) + "</tr>")
                    html_lines.append("</tbody></table>")
                else:
                    html_lines.append(f"<pre>{json.dumps(section_data, ensure_ascii=False)}</pre>")
            else:
                html_lines.append(f"<p>{section_data}</p>")
            html_lines.append("</section>")
        html_lines.append("</body></html>")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(html_lines))
        return str(path)

    def export_pdf(self, filename: str, data: Dict[str, Any]) -> Optional[str]:
        if fpdf is None:
            return None
        try:
            from fpdf import FPDF
        except Exception:
            return None
        path = self.output_directory / filename
        pdf = FPDF()
        pdf.set_auto_page_break(True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "System Audit Report", ln=True)
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 8, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(4)
        for section, section_data in data.items():
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 8, section, ln=True)
            pdf.set_font("Arial", "", 9)
            if isinstance(section_data, dict):
                for key, value in section_data.items():
                    value_text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
                    pdf.multi_cell(0, 6, f"{key}: {value_text}")
            elif isinstance(section_data, list):
                pdf.multi_cell(0, 6, f"Items: {len(section_data)}")
            else:
                pdf.multi_cell(0, 6, str(section_data))
            pdf.ln(2)
        try:
            pdf.output(str(path))
            return str(path)
        except Exception:
            return None


class Dashboard:

    def __init__(self, refresh_rate: float = 1.0) -> None:
        self.system_collector = SystemInfoCollector()
        self.cpu_collector = CPUCollector()
        self.memory_collector = MemoryCollector()
        self.disk_collector = DiskCollector()
        self.network_collector = NetworkCollector()
        self.gpu_collector = GPUCollector()
        self.sensor_collector = SensorCollector()
        self.process_collector = ProcessCollector()
        self.security_collector = SecurityCollector()
        self.port_collector = PortCollector()
        self.installed_collector = InstalledProgramsCollector()
        self.active_collector = ActiveConnectionCollector()
        self.benchmark_engine = BenchmarkEngine()
        self.diagnostic_engine = DiagnosticEngine()
        self.report_generator = ReportGenerator()
        self.refresh_rate = refresh_rate

    def build_header_panel(self, system_info: Dict[str, Any]) -> Panel:
        table = Table.grid(expand=True)
        table.add_column(ratio=2)
        table.add_column(ratio=1)
        table.add_row(f"Hostname: {system_info.get('hostname', '-')}", f"User: {system_info.get('user', '-')}")
        table.add_row(f"OS: {system_info.get('os_name', '-')}", f"Version: {system_info.get('os_version', '-')}")
        table.add_row(f"Architecture: {system_info.get('architecture', '-')}", f"Python: {system_info.get('python_version', '-')}")
        table.add_row(f"Date: {system_info.get('datetime', '-')}", f"Uptime: {system_info.get('uptime', '-')}")
        table.add_row(f"Manufacturer: {system_info.get('manufacturer', '-')}", f"Model: {system_info.get('model', '-')}")
        table.add_row(f"BIOS: {system_info.get('bios_version', '-')}", f"BIOS serial: {system_info.get('bios_serial', '-')}")
        return Panel(table, title="System Overview", box=box.ROUNDED, border_style="cyan")

    def build_cpu_panel(self, specs: Dict[str, Any], metrics: Dict[str, Any]) -> Panel:
        table = Table.grid(expand=True)
        table.add_column(ratio=2)
        table.add_column(ratio=1)
        table.add_row("CPU:", str(specs.get("name", "-")))
        table.add_row("Vendor:", str(specs.get("vendor", "-")))
        table.add_row("Physical cores:", str(specs.get("physical_cores", "-")))
        table.add_row("Logical cores:", str(specs.get("logical_cores", "-")))
        table.add_row("Min freq:", f"{safe_int(specs.get('min_freq'))} MHz")
        table.add_row("Max freq:", f"{safe_int(specs.get('max_freq'))} MHz")
        table.add_row("Current freq:", f"{safe_int(specs.get('current_freq'))} MHz")
        table.add_row("Global usage:", f"{metrics.get('overall', 0.0):.1f}%")
        table.add_row("Load avg:", ", ".join([f"{value:.2f}" for value in metrics.get("loadavg", (0.0, 0.0, 0.0))]))

        core_table = Table(show_header=True, header_style="bold white")
        core_table.add_column("Core")
        core_table.add_column("Usage")
        for index, value in enumerate(metrics.get("per_core", [])[:12]):
            core_table.add_row(str(index), f"{value:.1f}%")

        spark = ascii_sparkline(metrics.get("history", []))
        cpu_progress = Progress(
            TextColumn("CPU:"),
            BarColumn(bar_width=None, complete_style="magenta"),
            TextColumn("{task.percentage:>3.0f}%"),
            expand=True,
        )
        cpu_progress.add_task("cpu", total=100, completed=metrics.get("overall", 0.0))
        return Panel(Group(table, cpu_progress, Text(spark), core_table), title="CPU Monitoring", box=box.ROUNDED, border_style="magenta")

    def build_memory_panel(self, memory_info: Dict[str, Any]) -> Panel:
        table = Table.grid(expand=True)
        table.add_column(ratio=2)
        table.add_column(ratio=1)
        table.add_row("Total RAM:", human_bytes(memory_info.get("total")))
        table.add_row("Used RAM:", human_bytes(memory_info.get("used")))
        table.add_row("Free RAM:", human_bytes(memory_info.get("free")))
        table.add_row("Available:", human_bytes(memory_info.get("available")))
        percent = memory_info.get("percent", 0)
        table.add_row("Usage:", f"{percent:.1f}%")
        table.add_row("Swap total:", human_bytes(memory_info.get("swap_total")))
        table.add_row("Swap used:", human_bytes(memory_info.get("swap_used")))
        table.add_row("Swap free:", human_bytes(memory_info.get("swap_free")))
        table.add_row("Swap usage:", f"{memory_info.get('swap_percent', 0):.1f}%")
        status = "OK" if percent < 80 else "WARNING" if percent < 95 else "CRITICAL"
        memory_progress = Progress(
            TextColumn("RAM:"),
            BarColumn(bar_width=None, complete_style="green"),
            TextColumn("{task.percentage:>3.0f}%"),
            expand=True,
        )
        memory_progress.add_task("memory", total=100, completed=percent)
        return Panel(Group(table, memory_progress, Text(f"{percent:.1f}% - {status}")), title="Memory Monitoring", box=box.ROUNDED, border_style="green")

    def build_disk_panel(self, partitions: List[Dict[str, Any]], smart_info: List[Dict[str, Any]], io_data: Dict[str, Any]) -> Panel:
        disk_table = Table(show_header=True, header_style="bold cyan")
        disk_table.add_column("Mount")
        disk_table.add_column("FS")
        disk_table.add_column("Total", justify="right")
        disk_table.add_column("Used", justify="right")
        disk_table.add_column("Free", justify="right")
        disk_table.add_column("Usage", justify="right")
        for part in partitions[:8]:
            usage = part.get("usage")
            disk_table.add_row(
                str(part.get("mountpoint", "-")),
                str(part.get("fstype", "-")),
                human_bytes(getattr(usage, "total", None)),
                human_bytes(getattr(usage, "used", None)),
                human_bytes(getattr(usage, "free", None)),
                f"{getattr(usage, 'percent', 0):.1f}%" if usage else "-",
            )
        smart_table = Table(show_header=True, header_style="bold yellow")
        smart_table.add_column("Device")
        smart_table.add_column("Model")
        smart_table.add_column("Status")
        for item in smart_info[:4]:
            smart_table.add_row(str(item.get("device", "-")), str(item.get("model", "-")), str(item.get("status", "-")))
        io_text = Text(f"Reads: {io_data.get('read_count', 0)}  Writes: {io_data.get('write_count', 0)}  ReadBytes: {human_bytes(io_data.get('read_bytes', 0))}  WriteBytes: {human_bytes(io_data.get('write_bytes', 0))}")
        return Panel(Group(disk_table, smart_table, io_text), title="Disk Audit", box=box.ROUNDED, border_style="blue")

    def build_network_panel(self, interfaces: List[Dict[str, Any]], throughput: Dict[str, float], public_ip: str) -> Panel:
        network_meta = Table.grid(expand=True)
        network_meta.add_column(ratio=1)
        network_meta.add_column(ratio=1)
        local_ips = ", ".join({iface.get("ipv4", "-") for iface in interfaces if iface.get("ipv4") and iface.get("ipv4") != "-"}) or "-"
        macs = ", ".join({iface.get("mac", "-") for iface in interfaces if iface.get("mac") and iface.get("mac") != "-"}) or "-"
        network_meta.add_row("Local IP:", local_ips)
        network_meta.add_row("MAC addresses:", macs)
        network_meta.add_row("Public IP:", public_ip)

        table = Table(show_header=True, header_style="bold green")
        table.add_column("Interface")
        table.add_column("IPv4")
        table.add_column("Status")
        table.add_column("Speed")
        for iface in interfaces[:6]:
            table.add_row(  str(iface.get("name", "-")),  str(iface.get("ipv4", "-")),  "Up" if iface.get("is_up") else "Down",  f"{safe_int(iface.get('speed'))} Mbps"  )
        traffic = Text(f"Upload: {human_bytes(throughput.get('sent_rate', 0))}/s | Download: {human_bytes(throughput.get('recv_rate', 0))}/s")
        return Panel(Group(network_meta, table, traffic), title="Network Audit", box=box.ROUNDED, border_style="bright_blue")

    def build_gpu_panel(self, gpus: List[Dict[str, Any]]) -> Panel:
        if not gpus:
            return Panel("GPU not detected or GPUtil unavailable", title="GPU Audit", box=box.ROUNDED, border_style="red")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Name")
        table.add_column("Driver")
        table.add_column("VRAM")
        table.add_column("Used")
        table.add_column("Load")
        table.add_column("Temp")
        for gpu in gpus:
            table.add_row(
                str(gpu.get("name", "-")),
                str(gpu.get("driver", "-")),
                f"{safe_int(gpu.get('memory_total'))} MB",
                f"{safe_int(gpu.get('memory_used'))} MB",
                f"{gpu.get('load', 0):.0f}%",
                str(gpu.get("temperature", "-")),
            )
        return Panel(table, title="GPU Audit", box=box.ROUNDED, border_style="magenta")

    def build_process_panel(self, top_cpu: List[Dict[str, Any]], top_mem: List[Dict[str, Any]]) -> Panel:
        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("PID", justify="right")
        table.add_column("Name")
        table.add_column("CPU %", justify="right")
        table.add_column("Memory", justify="right")
        for proc in top_cpu[:10]:
            table.add_row(
                str(proc.get("pid", "-")),
                str(proc.get("name", "-")),
                f"{proc.get('cpu', 0.0):.1f}",
                human_bytes(proc.get("memory", 0)),
            )
        return Panel(table, title="Top Processes by CPU", box=box.ROUNDED, border_style="yellow")

    def build_security_panel(self, security: Dict[str, Any]) -> Panel:
        defender = security.get("defender", {})
        firewall = security.get("firewall", {})
        antivirus = security.get("antivirus", [])
        table = Table.grid(expand=True)
        table.add_column(ratio=2)
        table.add_column(ratio=1)
        table.add_row("Windows Defender:", "Enabled" if defender.get("enabled") else "Disabled")
        table.add_row("Real-time:", "On" if defender.get("realtime") else "Off")
        table.add_row("Firewall:", "Enabled" if firewall.get("enabled") else "Disabled")
        table.add_row("AV products:", str(len(antivirus)))
        table.add_row("Security score:", f"{security.get('security_score', 0)} / 100")
        table.add_row("Status:", security.get("status", "-"))
        return Panel(Group(table), title="Security Audit", box=box.ROUNDED, border_style="bright_red")

    def build_alert_panel(self, collected: Dict[str, Any]) -> Panel:
        warnings: List[str] = []
        status = "OK"
        style = "green"
        cpu_pct = collected["cpu_metrics"].get("overall", 0.0)
        ram_pct = collected["memory_info"].get("percent", 0)
        disk_pct = max((getattr(part["usage"], "percent", 0) for part in collected["disk_partitions"] if part.get("usage")), default=0)
        temp_values = []
        for temp_list in collected["sensors"].get("temperatures", {}).values():
            for entry in temp_list:
                temp_values.append(getattr(entry, "current", 0) or 0)
        temp_values.extend([item.get("current", 0) for item in collected["sensors"].get("wmi", []) if item.get("current") is not None])
        temp_pct = max(temp_values, default=0)
        if cpu_pct > 85:
            warnings.append(f"CPU critique : {cpu_pct:.1f}%")
        elif cpu_pct > 75:
            warnings.append(f"CPU élevé : {cpu_pct:.1f}%")
        if ram_pct > 90:
            warnings.append(f"RAM critique : {ram_pct:.1f}%")
        elif ram_pct > 80:
            warnings.append(f"RAM élevée : {ram_pct:.1f}%")
        if disk_pct > 90:
            warnings.append(f"Disque critique : {disk_pct:.1f}%")
        elif disk_pct > 80:
            warnings.append(f"Disque élevé : {disk_pct:.1f}%")
        if temp_pct > 85:
            warnings.append(f"Température critique : {temp_pct:.1f}°C")
        elif temp_pct > 75:
            warnings.append(f"Température élevée : {temp_pct:.1f}°C")
        if warnings:
            if any(value > threshold for value, threshold in [(cpu_pct, 85), (ram_pct, 90), (disk_pct, 90), (temp_pct, 85)]):
                status = "CRITICAL"
                style = "bold red"
            else:
                status = "WARNING"
                style = "bold yellow"
        else:
            warnings.append("Aucun problème critique détecté")
        alert_text = Text(style=style)
        alert_text.append(f"{status}\n", style=style)
        for line in warnings[:5]:
            alert_text.append(f"• {line}\n")
        return Panel(alert_text, title="Alerts", box=box.ROUNDED, border_style=style)

    def build_port_panel(self, ports: List[Dict[str, Any]]) -> Panel:
        table = Table(show_header=True, header_style="bold white")
        table.add_column("Local")
        table.add_column("Remote")
        table.add_column("Status")
        for item in ports[:12]:
            table.add_row(str(item.get("local", "-")), str(item.get("remote", "-")), str(item.get("status", "-")))
        return Panel(table, title="Open Ports / Connections", box=box.ROUNDED, border_style="white")

    def build_virtualization_panel(self, machines: List[str]) -> Panel:
        text = Text("Detected: " + ", ".join(machines))
        return Panel(text, title="Virtualization", box=box.ROUNDED, border_style="bright_blue")

    def build_score_panel(self, diagnostics: Dict[str, Any], benchmark: Dict[str, Any], security: Dict[str, Any], network_score: int, global_grade: str) -> Panel:
        score = diagnostics.get("score", 0)
        summary = Table.grid(expand=True)
        summary.add_column(ratio=1)
        summary.add_column(ratio=1)
        summary.add_row(Text(f"GLOBAL SCORE : {score}/100", style="bold bright_green"), Text(f"GRADE : {global_grade}", style="bold bright_blue"))
        summary.add_row("CPU:", f"{benchmark.get('cpu_score', 0)}/100")
        summary.add_row("RAM:", f"{benchmark.get('ram_score', 0)}/100")
        summary.add_row("Disk:", f"{benchmark.get('disk_score', 0)}/100")
        summary.add_row("Network:", f"{network_score}/100")
        summary.add_row("Security:", f"{security.get('security_score', 0)}/100")
        return Panel(summary, title="Global Health Score", box=box.ROUNDED, border_style="bright_green")

    def collect_all(self) -> Dict[str, Any]:
        system_info = self.system_collector.collect()
        cpu_specs = self.cpu_collector.collect_specs()
        cpu_metrics = self.cpu_collector.collect_metrics()
        memory_info = self.memory_collector.collect()
        partitions = self.disk_collector.collect_partitions()
        disk_smart = self.disk_collector.collect_smart()
        io_data = self.disk_collector.collect_io()
        interfaces = self.network_collector.collect_interfaces()
        throughput = self.network_collector.collect_throughput()
        public_ip = get_public_ip()
        gpus = self.gpu_collector.collect()
        sensors = self.sensor_collector.collect()
        top_cpu = self.process_collector.collect_top_cpu(20)
        top_mem = self.process_collector.collect_top_memory(20)
        security = self.security_collector.collect()
        ports = self.port_collector.collect(20)
        connections = self.active_collector.collect(20)
        installed_apps = self.installed_collector.collect()
        benchmark = self.benchmark_engine.collect()
        virtualization = detect_virtualization()
        network_score = self._network_score(interfaces, throughput)
        diagnostics = self.diagnostic_engine.evaluate(cpu_metrics.get("overall", 0.0), memory_info.get("percent", 0), partitions, sensors, security.get("security_score", 0))
        global_score = int((diagnostics.get("score", 0) + benchmark.get("cpu_score", 0) + benchmark.get("ram_score", 0) + benchmark.get("disk_score", 0) + security.get("security_score", 0) + network_score) / 6)
        global_grade = "A" if global_score >= 90 else "B" if global_score >= 75 else "C" if global_score >= 60 else "D"
        return {
            "system_info": system_info,
            "cpu_specs": cpu_specs,
            "cpu_metrics": cpu_metrics,
            "memory_info": memory_info,
            "disk_partitions": partitions,
            "disk_smart": disk_smart,
            "disk_io": io_data,
            "network_interfaces": interfaces,
            "network_throughput": throughput,
            "public_ip": public_ip,
            "gpus": gpus,
            "sensors": sensors,
            "top_cpu_processes": top_cpu,
            "top_memory_processes": top_mem,
            "security": security,
            "open_ports": ports,
            "active_connections": connections,
            "installed_apps": installed_apps,
            "benchmark": benchmark,
            "virtualization": virtualization,
            "diagnostics": diagnostics,
            "network_score": network_score,
            "global_score": global_score,
            "global_grade": global_grade,
        }

    def _network_score(self, interfaces: List[Dict[str, Any]], throughput: Dict[str, float]) -> int:
        fastest = max((iface.get("speed", 0) for iface in interfaces), default=0)
        if fastest >= 1000:
            score = 100
        elif fastest >= 200:
            score = 80
        elif fastest >= 100:
            score = 60
        else:
            score = 45
        if any(not iface.get("is_up") for iface in interfaces):
            score = min(score, 70)
        return score

    def export_report(self, collected: Dict[str, Any], report_format: str) -> List[str]:
        outputs: List[str] = []
        base_name = f"system_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if report_format in {"json", "all"}:
            outputs.append(self.report_generator.export_json(f"{base_name}.json", collected))
        if report_format in {"csv", "all"}:
            outputs.append(self.report_generator.export_csv(f"{base_name}.csv", collected))
        if report_format in {"html", "all"}:
            outputs.append(self.report_generator.export_html(f"{base_name}.html", collected))
        if report_format in {"pdf", "all"}:
            pdf_path = self.report_generator.export_pdf(f"{base_name}.pdf", collected)
            if pdf_path:
                outputs.append(pdf_path)
        return outputs

    def run(self, once: bool = False, report_format: Optional[str] = None) -> None:
        if psutil is None:
            console.print("[red]Required library psutil is missing. Install it with: python -m pip install psutil[/red]")
            return
        if once:
            collected = self.collect_all()
            self._print_summary(collected)
            if report_format:
                paths = self.export_report(collected, report_format)
                for path in paths:
                    console.print(f"[green]Report exported to:[/green] {path}")
            return

        layout = Layout(name="root")
        layout.split_column(
            Layout(name="header", size=11),
            Layout(name="body", ratio=3),
            Layout(name="footer", size=10),
        )
        layout["body"].split_row(Layout(name="left"), Layout(name="right", ratio=2))
        layout["left"].split_column(Layout(name="cpu", size=15), Layout(name="memory", size=12), Layout(name="disk", ratio=2))
        layout["right"].split_column(Layout(name="network", size=12), Layout(name="gpu", size=10), Layout(name="processes", ratio=2))
        layout["footer"].split_row(Layout(name="security"), Layout(name="alerts"), Layout(name="scores"), Layout(name="ports"))

        collected = self.collect_all()
        layout["header"].update(self.build_header_panel(collected["system_info"]))
        layout["left"]["cpu"].update(self.build_cpu_panel(collected["cpu_specs"], collected["cpu_metrics"]))
        layout["left"]["memory"].update(self.build_memory_panel(collected["memory_info"]))
        layout["left"]["disk"].update(self.build_disk_panel(collected["disk_partitions"], collected["disk_smart"], collected["disk_io"]))
        layout["right"]["network"].update(self.build_network_panel(collected["network_interfaces"], collected["network_throughput"], collected["public_ip"]))
        layout["right"]["gpu"].update(self.build_gpu_panel(collected["gpus"]))
        layout["right"]["processes"].update(self.build_process_panel(collected["top_cpu_processes"], collected["top_memory_processes"]))
        layout["footer"]["security"].update(self.build_security_panel(collected["security"]))
        layout["footer"]["alerts"].update(self.build_alert_panel(collected))
        layout["footer"]["scores"].update(self.build_score_panel(collected["diagnostics"], collected["benchmark"], collected["security"], collected["network_score"], collected["global_grade"]))
        layout["footer"]["ports"].update(self.build_port_panel(collected["open_ports"]))

        with Live(layout, console=console, screen=True, refresh_per_second=2):
            while True:
                try:
                    collected = self.collect_all()
                    layout["header"].update(self.build_header_panel(collected["system_info"]))
                    layout["left"]["cpu"].update(self.build_cpu_panel(collected["cpu_specs"], collected["cpu_metrics"]))
                    layout["left"]["memory"].update(self.build_memory_panel(collected["memory_info"]))
                    layout["left"]["disk"].update(self.build_disk_panel(collected["disk_partitions"], collected["disk_smart"], collected["disk_io"]))
                    layout["right"]["network"].update(self.build_network_panel(collected["network_interfaces"], collected["network_throughput"], collected["public_ip"]))
                    layout["right"]["gpu"].update(self.build_gpu_panel(collected["gpus"]))
                    layout["right"]["processes"].update(self.build_process_panel(collected["top_cpu_processes"], collected["top_memory_processes"]))
                    layout["footer"]["security"].update(self.build_security_panel(collected["security"]))
                    layout["footer"]["alerts"].update(self.build_alert_panel(collected))
                    layout["footer"]["scores"].update(self.build_score_panel(collected["diagnostics"], collected["benchmark"], collected["security"], collected["network_score"], collected["global_grade"]))
                    layout["footer"]["ports"].update(self.build_port_panel(collected["open_ports"]))
                    if report_format:
                        paths = self.export_report(collected, report_format)
                        for path in paths:
                            console.print(f"[green]Report exported to:[/green] {path}")
                        report_format = None
                    time.sleep(self.refresh_rate)
                except KeyboardInterrupt:
                    console.print("\nExiting System Control Center")
                    break
                except Exception as exc:
                    console.print(f"[red]Dashboard error:[/red] {exc}")
                    time.sleep(self.refresh_rate)

    def _print_summary(self, data: Dict[str, Any]) -> None:
        console.print(self.build_header_panel(data["system_info"]))
        console.print(self.build_cpu_panel(data["cpu_specs"], data["cpu_metrics"]))
        console.print(self.build_memory_panel(data["memory_info"]))
        console.print(self.build_security_panel(data["security"]))
        console.print(self.build_score_panel(data["diagnostics"], data["benchmark"], data["security"], data["network_score"], data["global_grade"]))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Advanced Windows system control center and diagnostics tool")
    parser.add_argument("--once", action="store_true", help="Collect data once and print summary")
    parser.add_argument("--export", choices=["json", "html", "csv", "pdf", "all"], help="Export a full audit report")
    parser.add_argument("--refresh", type=float, default=1.0, help="Refresh interval in seconds for live dashboard")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    Dashboard(refresh_rate=args.refresh).run(once=args.once or bool(args.export), report_format=args.export)


if __name__ == "__main__":
    main()

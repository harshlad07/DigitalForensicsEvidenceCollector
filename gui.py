import tkinter as tk
from tkinter import messagebox
from modules.data_collector import *
from modules.chart_generator import *
from modules.utils import *
from datetime import datetime
import os
import json
import threading

class ForensicsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensics Evidence Collector")
        self.root.geometry("500x500")

        # Checkbox options
        self.options = {
            "System Info": tk.BooleanVar(),
            "Processes": tk.BooleanVar(),
            "Network": tk.BooleanVar(),
            "USB": tk.BooleanVar(),
            "Recents": tk.BooleanVar(),
            "Save Detailed": tk.BooleanVar()
        }

        row = 0
        for key, var in self.options.items():
            tk.Checkbutton(root, text=key, variable=var).grid(row=row, column=0, sticky="w", padx=10)
            row += 1

        # Process tracking
        tk.Label(root, text="Track Process (name or PID):").grid(row=row, column=0, sticky="w", padx=10, pady=10)
        self.track_entry = tk.Entry(root)
        self.track_entry.grid(row=row, column=1)
        row += 1

        tk.Label(root, text="Monitor Duration (sec):").grid(row=row, column=0, sticky="w", padx=10)
        self.monitor_entry = tk.Entry(root)
        self.monitor_entry.insert(0, "0")
        self.monitor_entry.grid(row=row, column=1)
        row += 1

        # Run Button
        tk.Button(root, text="Run Forensic Scan", command=self.run_scan).grid(row=row, column=0, columnspan=2, pady=20)

        # Output Label
        self.status_label = tk.Label(root, text="Output folder will appear here...")
        self.status_label.grid(row=row+1, column=0, columnspan=2)

    def run_scan(self):
        # Run in a thread so GUI stays responsive
        threading.Thread(target=self._scan).start()

    def _scan(self):
        now = datetime.now()
        current_time_stamp = now.strftime("%Y-%m-%d_%H-%M-%S")
        base_name = f"report_{current_time_stamp}"
        track_name = self.track_entry.get().strip()

        if track_name:
            base_name += f"_{track_name.replace(' ', '_').split(".exe")[0]}"

        output_dir = os.path.join("Report", base_name)
        os.makedirs(output_dir, exist_ok=True)

        report = {"timestamp": now.strftime("%Y-%m-%d %H:%M:%S")}
        detailed = self.options["Save Detailed"].get()

        if self.options["System Info"].get():
            sysinfo = collect_system_info()
            report["system_info"] = sysinfo
            if detailed:
                os.makedirs(f"{output_dir}/system", exist_ok=True)
                with open(f"{output_dir}/system/system_info.json", "w") as f:
                    json.dump(sysinfo, f, indent=4)

        if self.options["Processes"].get():
            proc = collect_running_processes()
            report["processes"] = proc
            if detailed:
                os.makedirs(f"{output_dir}/processes", exist_ok=True)
                with open(f"{output_dir}/processes/process_list.json", "w") as f:
                    json.dump(proc, f, indent=4)

        if self.options["Network"].get():
            net = collect_network_connections()
            report["network_connections"] = net
            if detailed:
                os.makedirs(f"{output_dir}/network", exist_ok=True)
                net_path = f"{output_dir}/network/net_connections.json"
                with open(net_path, "w") as f:
                    json.dump(net, f, indent=4)
                plot_visited_domains(net_path, output_dir)

        if self.options["USB"].get():
            usb = get_usb_history()
            report["usb_history"] = usb
            if detailed:
                os.makedirs(f"{output_dir}/usb", exist_ok=True)
                with open(f"{output_dir}/usb/usb_history.json", "w") as f:
                    json.dump(usb, f, indent=4)

        if self.options["Recents"].get():
            recents = get_recent_files()
            report["recent_files"] = recents
            if detailed:
                os.makedirs(f"{output_dir}/recents", exist_ok=True)
                with open(f"{output_dir}/recents/recent_files.json", "w") as f:
                    json.dump(recents, f, indent=4)

        if track_name:
            proc = find_process_by_name_or_pid(track_name)
            if proc:
                monitor_secs = int(self.monitor_entry.get().strip())
                track_report = {
                    "process_details": get_process_details(proc),
                    "logs": get_logs_for_pid(proc.pid)
                }
                if monitor_secs > 0:
                    track_report["live_monitoring"] = monitor_process_live(proc, monitor_secs)
                os.makedirs(f"{output_dir}/tracked", exist_ok=True)
                with open(f"{output_dir}/tracked/{proc.name()}_{proc.pid}.json", "w") as f:
                    json.dump(track_report, f, indent=4)
                plot_monitoring_data(f"{output_dir}/tracked/{proc.name()}_{proc.pid}.json",output_dir)

        # Save main JSON
        report_path = os.path.join(output_dir, "forensic_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=4)

        hash_val = hash_file(report_path)
        compress_report(report_path, hash_val,output_dir)

        self.status_label.config(text=f"✅ Report saved in: {output_dir}")

        messagebox.showinfo("Success", "Forensic scan completed!")

if __name__ == "__main__":
    root = tk.Tk()
    app = ForensicsGUI(root)
    root.mainloop()

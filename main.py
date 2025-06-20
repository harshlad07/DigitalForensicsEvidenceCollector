import os
import json
import argparse
from datetime import datetime
from colorama import init, Fore, Style
init(autoreset=True)
from modules.chart_generator import plot_monitoring_data,plot_visited_domains
from modules.data_collector import (
    collect_system_info,
    collect_running_processes,
    collect_network_connections,
    find_process_by_name_or_pid,
    get_process_details,
    get_usb_history,
    get_logs_for_pid,
    monitor_process_live,
    get_recent_files
)
from modules.utils import hash_file, compress_report

def generate_forensic_report(options):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    combined_report = {
        "timestamp": timestamp,
    }
    now = datetime.now()
    current_time_stamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    base_name = f"report_{current_time_stamp}"

    if options.track:
        proc = find_process_by_name_or_pid(options.track)
        if proc:
            base_name += f"_{proc.name().replace(' ', '_').split(".exe")[0]}"

    output_dir = os.path.join("Report", base_name)
    os.makedirs(output_dir, exist_ok=True)


    if options.sysinfo or options.all:
        sys_info = collect_system_info()
        combined_report["system_info"] = sys_info
        if options.save_detailed:
            os.makedirs(f"{output_dir}/system", exist_ok=True)
            with open(f"{output_dir}/system/system_info.json", "w") as f:
                json.dump(sys_info, f, indent=4)

    if options.processes or options.all:
        processes = collect_running_processes()
        combined_report["running_processes"] = processes
        if options.save_detailed:
            os.makedirs(f"{output_dir}/processes", exist_ok=True)
            with open(f"{output_dir}/processes/process_list.json", "w") as f:
                json.dump(processes, f, indent=4)

    if options.network or options.all:
        connections = collect_network_connections()
        combined_report["network_connections"] = connections
        if options.save_detailed:
            os.makedirs(f"{output_dir}/network", exist_ok=True)
            net_path = f"{output_dir}/network/net_connections.json"
            with open(net_path, "w") as f:
                json.dump(connections, f, indent=4)

            # 📊 Plot chart of visited domains
            plot_visited_domains(net_path, output_dir)


    if options.usb or options.all:
        usb = get_usb_history()
        combined_report["usb_history"] = usb
        if options.save_detailed:
            os.makedirs(f"{output_dir}/usb", exist_ok=True)
            with open(f"{output_dir}/usb/usb_history.json", "w") as f:
                json.dump(usb, f, indent=4)

    if options.recent or options.all:
        recents = get_recent_files()
        combined_report["recent_files"] = recents
        if options.save_detailed:
            os.makedirs(f"{output_dir}/recents", exist_ok=True)
            with open(f"{output_dir}/recents/recent_files.json", "w") as f:
                json.dump(recents, f, indent=4)

    if options.track:
        proc = find_process_by_name_or_pid(options.track)
        if proc:
            print(Fore.BLUE + Style.BRIGHT +"\n" +f"*"*20)
            print(Fore.GREEN + Style.BRIGHT + f"[✔] Tracking process: {proc.name()} (PID {proc.pid})")
            proc_report = {
                "process_details": get_process_details(proc),
                "system_logs": get_logs_for_pid(proc.pid)
            }

            if options.monitor > 0:
                print(Fore.YELLOW + Style.BRIGHT + f"[⏳] Monitoring for {options.monitor} seconds...")
                proc_report["live_monitoring"] = monitor_process_live(proc, options.monitor)

            safe_name = proc.name().replace(" ", "_")
            report_path = f"{output_dir}/tracked/{safe_name}_{proc.pid}.json"
            os.makedirs(f"{output_dir}/tracked", exist_ok=True)
            with open(report_path, "w") as f:
                json.dump(proc_report, f, indent=4)
            print(Fore.GREEN + Style.BRIGHT + f"[✔] Process report saved to {report_path}")
            if options.monitor > 0:
                plot_monitoring_data(report_path,f'{output_dir}')
        else:
            print(Fore.RED + Style.BRIGHT + "[✘] Process not found.")
    

    # Save combined report
    # report_path = f"{output_dir}/forensic_report.json"
    report_path = os.path.join(output_dir, "forensic_report.json")

    with open(report_path, "w") as f:
        json.dump(combined_report, f, indent=4)

    print(Fore.GREEN + Style.BRIGHT + "[✔] Combined JSON report created.")

    # Hash & compress
    sha256_hash = hash_file(report_path)
    print(Fore.GREEN + Style.BRIGHT + f"[✔] SHA-256 Hash: {sha256_hash}")
    compress_report(report_path, sha256_hash,output_dir)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Digital Forensics Evidence Collector")
    parser.add_argument("--all", action="store_true", help="Run full forensic scan")
    parser.add_argument("--processes", action="store_true", help="Collect running processes")
    parser.add_argument("--network", action="store_true", help="Collect open network connections")
    parser.add_argument("--usb", action="store_true", help="Collect USB device history")
    parser.add_argument("--recent", action="store_true", help="Collect recently accessed files")
    parser.add_argument("--sysinfo", action="store_true", help="Collect basic system information")
    parser.add_argument("--track", type=str, help="Track a process by name or PID")
    parser.add_argument("--monitor", type=int, default=0, help="Monitor tracked process for N seconds")
    parser.add_argument("--save-detailed", action="store_true", help="Save each module's data into separate structured files and folders.")


    args = parser.parse_args()
    return args


if __name__ == "__main__":
    options = parse_arguments()

    # If no flags are passed, show help and exit
    if not any(vars(options).values()):
        print(Fore.RED + Style.BRIGHT + "\n[!] No options provided. Use --help to see available options.")
    else:
        generate_forensic_report(options)

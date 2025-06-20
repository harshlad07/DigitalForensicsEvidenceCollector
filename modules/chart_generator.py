import json
import os
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime


def plot_visited_domains(json_path, output_dir):
    with open(json_path, "r") as f:
        data = json.load(f)

    domains = [conn["domain"] for conn in data if conn.get("domain")]
    counter = Counter(domains)
    if not counter:
        print("[!] No domain names found for chart.")
        return

    top = counter.most_common(10)
    labels, counts = zip(*top)

    plt.figure(figsize=(10, 6))
    plt.barh(labels, counts, color="skyblue")
    plt.xlabel("Connections")
    plt.title("Top Visited Domains (Live)")
    plt.tight_layout()

    os.makedirs(os.path.join(output_dir, "charts"), exist_ok=True)
    plt.savefig(os.path.join(output_dir, "charts", "top_domains.png"))
    plt.close()
    print(f"[✔] Domain chart saved to {output_dir}/charts/top_domains.png")

def plot_monitoring_data(json_file,outpath):
    with open(json_file, "r") as f:
        data = json.load(f)

    if "live_monitoring" not in data:
        print("[!] No monitoring data found.")
        return

    monitoring = data["live_monitoring"]
    if not monitoring:
        print("[!] Monitoring data is empty.")
        return

    timestamps = [datetime.fromtimestamp(d["timestamp"]) for d in monitoring]
    cpu = [d["cpu_percent"] for d in monitoring]
    mem = [d["memory_info"]["rss"] / (1024 ** 2) for d in monitoring]  # Convert to MB

    os.makedirs(f"{outpath}/charts", exist_ok=True)

    # CPU Chart
    plt.figure(figsize=(8, 4))
    plt.plot(timestamps, cpu, marker="o", label="CPU %")
    plt.title("CPU Usage Over Time")
    plt.xlabel("Timestamp")
    plt.ylabel("CPU %")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"{outpath}/charts/cpu_usage.png")
    plt.close()

    # Memory Chart
    plt.figure(figsize=(8, 4))
    plt.plot(timestamps, mem, marker="o", color="orange", label="Memory RSS (MB)")
    plt.title("Memory Usage Over Time")
    plt.xlabel("Timestamp")
    plt.ylabel("Memory (MB)")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(f"{outpath}/charts/memory_usage.png")
    plt.close()

    print(f"[✔] Charts saved inf {outpath}/charts/")
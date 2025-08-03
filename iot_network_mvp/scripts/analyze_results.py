"""
Post-process CSV output from scaling_test.py and produce detailed summary statistics, including per-sensor latency percentiles and success rates.

Usage:
  python3 analyze_results.py --input scaling_results.csv [--summary-output summary.txt] [--csv-output per_sensor_summary.csv] [--json-output summary.json]
"""
import argparse
import csv
import json
import sys
from collections import defaultdict
from statistics import mean


def percentile(sorted_list, perc):
    if not sorted_list:
        return None
    k = (len(sorted_list) - 1) * (perc / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_list) - 1)
    if f == c:
        return sorted_list[int(k)]
    d0 = sorted_list[f] * (c - k)
    d1 = sorted_list[c] * (k - f)
    return d0 + d1


def safe_float(x):
    try:
        return float(x)
    except Exception:
        return None


def summarize(data):
    total_messages = len(data)
    error_count = 0
    per_sensor = defaultdict(list)
    for r in data:
        status = r.get("status", "").lower()
        lat = safe_float(r.get("latency_secs"))
        if status == "error" or lat is None:
            error_count += 1
        per_sensor[r["sensor_id"]].append({"latency": lat, "status": status})

    summary = {
        "total_messages": total_messages,
        "total_errors": error_count,
        "overall_success_rate": None,
        "per_sensor": {},
    }
    success_count = total_messages - error_count
    summary["overall_success_rate"] = (success_count / total_messages) * 100 if total_messages else 0

    for sensor_id, entries in sorted(per_sensor.items()):
        latencies = [e["latency"] for e in entries if isinstance(e.get("latency"), (int, float))]
        total = len(entries)
        successful = len([e for e in entries if e.get("status") not in ("error",)])
        failures = total - successful
        success_rate = (successful / total) * 100 if total else 0
        sensor_summary = {
            "total": total,
            "success": successful,
            "failures": failures,
            "success_rate_percent": round(success_rate, 2),
        }
        if latencies:
            sorted_lat = sorted(latencies)
            sensor_summary.update({
                "avg_latency_secs": round(mean(sorted_lat), 4),
                "median_latency_secs": round(percentile(sorted_lat, 50), 4),
                "p90_latency_secs": round(percentile(sorted_lat, 90), 4),
                "p99_latency_secs": round(percentile(sorted_lat, 99), 4),
            })
        else:
            sensor_summary.update({
                "avg_latency_secs": None,
                "median_latency_secs": None,
                "p90_latency_secs": None,
                "p99_latency_secs": None,
            })
        summary["per_sensor"][sensor_id] = sensor_summary
    return summary


def format_text_summary(summary_dict):
    lines = []
    lines.append(f"Total messages: {summary_dict['total_messages']}")
    lines.append(f"Total errors/failures: {summary_dict['total_errors']}")
    lines.append(f"Overall success rate: {summary_dict['overall_success_rate']:.2f}%")
    lines.append("")
    lines.append("Per-sensor breakdown:")
    for sensor_id, s in summary_dict["per_sensor"].items():
        lines.append(f"- {sensor_id}:")
        lines.append(f"    messages: {s['total']}, success: {s['success']}, failures: {s['failures']}, success_rate: {s['success_rate_percent']}%")
        if s["avg_latency_secs"] is not None:
            lines.append(f"    avg_latency: {s['avg_latency_secs']}s, median: {s['median_latency_secs']}s, p90: {s['p90_latency_secs']}s, p99: {s['p99_latency_secs']}s")
        else:
            lines.append("    latency: no successful samples to compute stats")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Analyze scaling test CSV results with richer summary")
    parser.add_argument("--input", required=True, help="CSV file produced by scaling_test.py")
    parser.add_argument("--summary-output", help="Path to write human-readable summary text")
    parser.add_argument("--csv-output", help="Path to write per-sensor summary CSV")
    parser.add_argument("--json-output", help="Path to write machine-readable JSON summary")
    args = parser.parse_args()

    data = []
    try:
        with open(args.input, newline="") as csvf:
            reader = csv.DictReader(csvf)
            for r in reader:
                data.append(r)
    except FileNotFoundError:
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    summary = summarize(data)

    text_summary = format_text_summary(summary)
    print(text_summary)

    if args.summary_output:
        with open(args.summary_output, "w") as f:
            f.write(text_summary + "\n")
        print(f"[+] Written text summary to {args.summary_output}")

    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Written JSON summary to {args.json_output}")

    if args.csv_output:
        fieldnames = ["sensor_id", "total", "success", "failures", "success_rate_percent", "avg_latency_secs", "median_latency_secs", "p90_latency_secs", "p99_latency_secs"]
        try:
            with open(args.csv_output, "w", newline="") as outcsv:
                writer = csv.DictWriter(outcsv, fieldnames=fieldnames)
                writer.writeheader()
                for sid, s in summary["per_sensor"].items():
                    row = {"sensor_id": sid, **s}
                    writer.writerow(row)
            print(f"[+] Written per-sensor CSV summary to {args.csv_output}")
        except Exception as e:
            print(f"[!] Failed to write CSV summary: {e}")


if __name__ == "__main__":
    main()

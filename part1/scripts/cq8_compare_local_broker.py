import csv
import io
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt


TSHARK_FALLBACK = Path(r"C:\Program Files\Wireshark\tshark.exe")
LOCAL_ADDRESSES = {"127.0.0.1", "::1"}

# Keep the script self-contained, including figure generation.
CORE_FIELDS = [
    "frame.number",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "ip.dst",
    "ipv6.dst",
    "tcp.dstport",
    "tcp.stream",
]

MQTT_FIELDS = CORE_FIELDS + ["mqtt.msgtype", "mqtt.topic"]


def find_root():
    here = Path(__file__).resolve().parent
    for base in (here, here.parent, here.parent.parent, Path.cwd(), Path.cwd().parent):
        if (base / "docs").exists():
            return base
    return here.parent.parent


ROOT = find_root()
FIGURES_DIR = ROOT / "part1" / "figures"


def find_pcap(filename):
    for base in (Path(__file__).resolve().parent, Path.cwd(), ROOT):
        for path in (base / filename, base / "docs" / filename):
            if path.exists():
                return path
    return ROOT / "docs" / filename


def tshark_executable():
    path = shutil.which("tshark") or (str(TSHARK_FALLBACK) if TSHARK_FALLBACK.exists() else None)
    if not path:
        raise FileNotFoundError(f"tshark not found: {TSHARK_FALLBACK}")
    return path


def read_tshark_fields(pcap_path, display_filter, fields):
    # Repeated MQTT fields are joined with '|', then split in Python.
    command = [
        tshark_executable(),
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=|",
    ]
    for field in fields:
        command += ["-e", field]

    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return [] if not result.stdout.strip() else list(csv.DictReader(io.StringIO(result.stdout), delimiter="\t"))


def split_values(value):
    return value.split("|") if value else []


def value_at(values, index):
    return values[index] if index < len(values) else ""


def to_int(value):
    return int(value) if value else -1


def mqtt_events(pcap_path):
    rows = read_tshark_fields(pcap_path, "mqtt && !_ws.malformed", MQTT_FIELDS)
    repeated_fields = MQTT_FIELDS[len(CORE_FIELDS) :]
    events = []

    for row in rows:
        # One TCP frame can carry multiple MQTT messages.
        repeated = {field: split_values(row[field]) for field in repeated_fields}
        for index in range(max(1, len(repeated["mqtt.msgtype"]))):
            event = {field: row[field] for field in CORE_FIELDS}
            event.update({field: value_at(repeated[field], index) for field in repeated_fields})
            event.update(
                {
                    "frame": to_int(row["frame.number"]),
                    "stream": to_int(row["tcp.stream"]),
                    "type": to_int(event["mqtt.msgtype"]),
                    "ip.dst.effective": row["ip.dst"] or row["ipv6.dst"],
                }
            )
            events.append(event)

    return sorted(events, key=lambda item: (item["frame"], item["stream"]))


def topic_layers(topic):
    return len([level for level in topic.split("/") if level])


def local_publish_messages(pcap_path):
    messages = []
    for event in mqtt_events(pcap_path):
        # CQ8 counts client PUBLISH messages sent to the local broker.
        to_local_broker = event["tcp.dstport"] == "1883" and event["ip.dst.effective"] in LOCAL_ADDRESSES
        if event["type"] == 3 and to_local_broker and event["mqtt.topic"]:
            event["layers"] = topic_layers(event["mqtt.topic"])
            messages.append(event)
    return messages


def main():
    captures = {name: local_publish_messages(find_pcap(f"{name}.pcapng")) for name in ("A", "B")}
    histograms = {name: Counter(message["layers"] for message in messages) for name, messages in captures.items()}

    # Save the histogram used in the report.
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    figure_path = FIGURES_DIR / "cq8_histogram.png"
    all_layers = sorted(set().union(*(histogram.keys() for histogram in histograms.values())))
    x_positions = list(range(len(all_layers)))
    bar_width = 0.38

    plt.figure(figsize=(7, 4.5))
    for offset, name in [(-bar_width / 2, "A"), (bar_width / 2, "B")]:
        plt.bar(
            [x + offset for x in x_positions],
            [histograms[name].get(layer, 0) for layer in all_layers],
            width=bar_width,
            label=f"{name}.pcapng",
        )

    plt.xticks(x_positions, [str(layer) for layer in all_layers])
    plt.xlabel("Topic layers")
    plt.ylabel("Publish messages")
    plt.title("Local broker publish topic layers")
    plt.legend()
    plt.tight_layout()
    plt.savefig(figure_path, dpi=160)
    plt.close()

    print("CQ8")
    print("---")
    print("Publish messages directed to the local MQTT broker, grouped by topic layers:")
    print(f"CQ8a Answer (A.pcapng total): {len(captures['A'])}")
    print(f"CQ8b Answer (B.pcapng total): {len(captures['B'])}\n")

    for name in ("A", "B"):
        print(f"{name}.pcapng histogram:")
        for layer in all_layers:
            print(f"- layers={layer}: {histograms[name].get(layer, 0)}")
        print()

    print(f"Figure saved to: {figure_path}")


if __name__ == "__main__":
    main()

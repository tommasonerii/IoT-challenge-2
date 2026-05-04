import csv
import io
import shutil
import subprocess
from pathlib import Path


TSHARK_FALLBACK = Path(r"C:\Program Files\Wireshark\tshark.exe")
LOCAL_ADDRESSES = {"127.0.0.1", "::1"}

# Keep the script standalone for report verification.
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

MQTT_FIELDS = CORE_FIELDS + ["mqtt.msgtype", "mqtt.clientid", "mqtt.topic"]


def find_pcap(filename):
    here = Path(__file__).resolve().parent
    for base in (here, here.parent, here.parent.parent, Path.cwd(), Path.cwd().parent):
        for path in (base / filename, base / "docs" / filename):
            if path.exists():
                return path
    return here.parent.parent / "docs" / filename


B_PCAP = find_pcap("B.pcapng")


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


def wildcard_count(topic_filter):
    return topic_filter.count("+") + topic_filter.count("#")


events = mqtt_events(B_PCAP)

# CONNECT packets map each stream to the subscriber client id.
stream_clientids = {
    event["stream"]: event["mqtt.clientid"] or f"stream-{event['stream']}"
    for event in events
    if event["type"] == 1
}

matching_subscribes = []
for event in events:
    # A local broker request targets loopback TCP port 1883.
    to_local_broker = event["tcp.dstport"] == "1883" and event["ip.dst.effective"] in LOCAL_ADDRESSES
    if event["type"] == 8 and to_local_broker and wildcard_count(event["mqtt.topic"]) >= 2:
        matching_subscribes.append(event)

print("CQ7")
print("---")
print("MQTT SUBSCRIBE requests directed to the local broker with a topic filter containing at least two wildcards:")
print(f"Answer: {len(matching_subscribes)}\n")

if not matching_subscribes:
    print("- none")
else:
    for event in matching_subscribes:
        clientid = stream_clientids.get(event["stream"], f"stream-{event['stream']}")
        print(
            f"- frame={event['frame']}, clientid={clientid}, "
            f"topic_filter={event['mqtt.topic']}, wildcards={wildcard_count(event['mqtt.topic'])}"
        )

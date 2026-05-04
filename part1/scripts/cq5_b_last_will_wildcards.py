import csv
import io
import shutil
import subprocess
from pathlib import Path


TSHARK_FALLBACK = Path(r"C:\Program Files\Wireshark\tshark.exe")

# Keep the script self-contained for submission.
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

MQTT_FIELDS = CORE_FIELDS + [
    "mqtt.msgtype",
    "mqtt.clientid",
    "mqtt.conflag.willflag",
    "mqtt.willtopic",
    "mqtt.willmsg",
    "mqtt.topic",
    "mqtt.msg",
]


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
                    "ip.src.effective": row["ip.src"] or row["ipv6.src"],
                    "ip.dst.effective": row["ip.dst"] or row["ipv6.dst"],
                }
            )
            events.append(event)

    return sorted(events, key=lambda item: (item["frame"], item["stream"]))


def topic_matches(topic_filter, topic):
    # MQTT wildcard rule: '#' matches only as the last filter level.
    filter_levels, topic_levels = topic_filter.split("/"), topic.split("/")
    for index, level in enumerate(filter_levels):
        if level == "#":
            return index == len(filter_levels) - 1
        if index >= len(topic_levels) or (level != "+" and level != topic_levels[index]):
            return False
    return len(topic_levels) == len(filter_levels)


events = mqtt_events(B_PCAP)

# CONNECT packets define the stream client and optional Last Will.
streams = {}
for event in events:
    stream = streams.setdefault(event["stream"], {"clientid": "", "will": None})
    if event["type"] == 1:
        clientid = event["mqtt.clientid"] or f"stream-{event['stream']}"
        stream["clientid"] = event["mqtt.clientid"]
        if event["mqtt.conflag.willflag"] == "True" or event["mqtt.willtopic"]:
            stream["will"] = {
                "topic": event["mqtt.willtopic"],
                "payload": event["mqtt.willmsg"],
                "frame": event["frame"],
                "stream": event["stream"],
                "clientid": clientid,
            }

wills = [stream["will"] for stream in streams.values() if stream["will"]]

# Keep only SUBSCRIBE filters that really use MQTT wildcards.
wildcard_subscriptions = []
for event in events:
    topic_filter = event["mqtt.topic"]
    if event["type"] == 8 and ("+" in topic_filter or "#" in topic_filter):
        wildcard_subscriptions.append(
            {
                "frame": event["frame"],
                "stream": event["stream"],
                "clientid": streams[event["stream"]]["clientid"] or f"stream-{event['stream']}",
                "filter": topic_filter,
            }
        )

matches = []
receiving_subscribers = {}

for event in events:
    # A broker delivery is a PUBLISH sent from TCP port 1883.
    if event["type"] != 3 or event["tcp.srcport"] != "1883":
        continue

    for will in wills:
        same_topic = event["mqtt.topic"] == will["topic"]
        same_payload = not will["payload"] or event["mqtt.msg"] == will["payload"]
        if not (same_topic and same_payload):
            continue

        # Count only subscribers that matched through an earlier wildcard filter.
        for sub in wildcard_subscriptions:
            if sub["stream"] == event["stream"] and sub["frame"] < event["frame"] and topic_matches(sub["filter"], event["mqtt.topic"]):
                receiving_subscribers[sub["stream"]] = sub["clientid"]
                matches.append((event, will, sub))

print("CQ5")
print("---")
print("MQTT subscribers that receive a Last Will through a wildcard subscription:")
print(f"Answer: {len(receiving_subscribers)}\n")

print("Last Will declarations:")
for will in wills:
    print(f"- frame={will['frame']}, stream={will['stream']}, clientid={will['clientid']}, topic={will['topic']}")

print("\nMatched wildcard subscriber deliveries:")
if not matches:
    print("- none")
else:
    for event, will, sub in matches:
        print(
            f"- publish_frame={event['frame']}, subscriber={sub['clientid']}, "
            f"subscription={sub['filter']}, will_topic={will['topic']}, will_client={will['clientid']}"
        )

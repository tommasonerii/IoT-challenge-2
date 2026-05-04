import csv
import io
import shutil
import subprocess
from pathlib import Path


TSHARK_FALLBACK = Path(r"C:\Program Files\Wireshark\tshark.exe")
HIVEMQ_FALLBACK_IPS = {"18.192.151.104", "35.158.34.213", "35.158.43.69"}

# Keep all needed helpers inside this file for submission.
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
    "mqtt.topic",
    "mqtt.msg",
    "mqtt.retain",
]

DNS_FIELDS = ["frame.number", "dns.qry.name", "dns.a"]


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


def read_tshark_fields(pcap_path, display_filter, fields, repeated=False):
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
    ]
    if repeated:
        # Repeated MQTT fields are joined with '|', then split in Python.
        command += ["-E", "occurrence=a", "-E", "aggregator=|"]
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


def split_values(value, separator="|"):
    return value.split(separator) if value else []


def value_at(values, index):
    return values[index] if index < len(values) else ""


def to_int(value):
    return int(value) if value else -1


def hivemq_ips(pcap_path):
    # Prefer DNS answers from the capture; keep known IPs as a fallback.
    rows = read_tshark_fields(pcap_path, 'dns && dns.qry.name == "broker.hivemq.com"', DNS_FIELDS)
    addresses = {
        address.strip()
        for row in rows
        for address in split_values(row["dns.a"], separator=",")
        if address.strip()
    }
    return addresses or HIVEMQ_FALLBACK_IPS


def mqtt_events(pcap_path):
    rows = read_tshark_fields(pcap_path, "mqtt && !_ws.malformed", MQTT_FIELDS, repeated=True)
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


def is_empty_payload(value):
    # Empty retained PUBLISH erases the retained value for that topic.
    return value in {"", "<MISSING>"}


hivemq_addresses = hivemq_ips(B_PCAP)
events = mqtt_events(B_PCAP)

# CONNECT packets map each TCP stream to a client identifier.
stream_clientids = {
    event["stream"]: event["mqtt.clientid"] or f"stream-{event['stream']}"
    for event in events
    if event["type"] == 1
}

erase_messages = []
visible_previous_erases = []
retained_topics_seen = set()

for event in events:
    # CQ6 concerns retained PUBLISH messages sent to the HiveMQ broker.
    to_hivemq = event["tcp.dstport"] == "1883" and event["ip.dst.effective"] in hivemq_addresses
    if event["type"] != 3 or event["mqtt.retain"] != "True" or not to_hivemq:
        continue

    topic = event["mqtt.topic"]
    if is_empty_payload(event["mqtt.msg"]):
        erase_messages.append(event)
        if topic in retained_topics_seen:
            visible_previous_erases.append(event)
    else:
        retained_topics_seen.add(topic)

# Count each client once, using its first erase message.
clients = {}
for event in erase_messages:
    clientid = stream_clientids.get(event["stream"], f"stream-{event['stream']}")
    clients.setdefault(clientid, event)

long_clientids = [clientid for clientid in clients if len(clientid.encode("utf-8")) > 7]

print("CQ6")
print("---")
print("HiveMQ broker IPs found from DNS:")
print(f"- {', '.join(sorted(hivemq_addresses))}\n")

print("CQ6a")
print("-----")
print("Different clients that sent at least one retained empty PUBLISH to erase a retained value:")
print(f"Answer: {len(clients)}\n")

for clientid in sorted(clients):
    event = clients[clientid]
    print(
        f"- clientid={clientid}, length={len(clientid.encode('utf-8'))}, "
        f"first_erase_frame={event['frame']}, topic={event['mqtt.topic']}"
    )

print("\nCQ6b")
print("-----")
print("Clients from CQ6a with client identifier strictly longer than 7 bytes:")
print(f"Answer: {len(long_clientids)}\n")

if not long_clientids:
    print("- none")
else:
    for clientid in sorted(long_clientids):
        print(f"- {clientid}: length={len(clientid.encode('utf-8'))}")

print("\nVisible prior retained-value check:")
print(
    f"- {len(visible_previous_erases)} erase messages have a previous retained value "
    "visible earlier in the capture for the same HiveMQ topic."
)

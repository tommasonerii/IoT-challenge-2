import shutil
import subprocess
from pathlib import Path


def find_docs_dir():
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir.parent.parent / "docs",
        script_dir.parent / "docs",
        script_dir / "docs",
        Path.cwd() / "docs",
        Path.cwd().parent / "docs",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return script_dir.parent.parent / "docs"


DOCS_DIR = find_docs_dir()
TSHARK_FALLBACK = Path(r"C:\Program Files\Wireshark\tshark.exe")
A_PCAP = DOCS_DIR / "A.pcapng"
BROKER_PORT = "1885"

# Wireshark does not always decode MQTT-SN automatically on this port.
# This is the TShark equivalent of setting MQTT-SN port 1885 in Wireshark:
# Edit -> Preferences -> Protocols -> MQTT-SN.
MQTTSN_DECODE_AS = "udp.port==1885,mqttsn"

FIELDS = [
    "frame.number",
    "ip.src",
    "udp.srcport",
    "ip.dst",
    "udp.dstport",
    "mqttsn.msg.type",
    "mqttsn.topic",
    "mqttsn.client.id",
]


def tshark_executable():
    found = shutil.which("tshark")
    if found:
        return found
    if TSHARK_FALLBACK.exists():
        return str(TSHARK_FALLBACK)
    raise FileNotFoundError(
        "tshark not found in PATH and fallback path does not exist: "
        f"{TSHARK_FALLBACK}"
    )


def read_tshark_fields(pcap_path, display_filter, fields, decode_as=None):
    command = [tshark_executable()]

    if decode_as:
        command.extend(["-d", decode_as])

    command.extend([
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
    ])

    for field in fields:
        command.extend(["-e", field])

    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    lines = result.stdout.splitlines()
    if not lines:
        return []

    header = lines[0].split("\t")
    rows = []
    for line in lines[1:]:
        values = line.split("\t")
        values += [""] * (len(header) - len(values))
        rows.append(dict(zip(header, values)))

    return rows


def to_int(value):
    return int(value) if value else -1


def has_loopback_duplicate_fields(packet):
    # TShark can expose duplicate Linux loopback/SLL views as comma-separated
    # IP fields such as "127.0.0.1,127.0.0.1". Treat those rows as one capture
    # artifact, not as an additional logical protocol message.
    return "," in packet.get("ip.src", "") or "," in packet.get("ip.dst", "")


rows = read_tshark_fields(
    A_PCAP,
    "mqttsn && !icmp && !_ws.malformed",
    FIELDS,
    decode_as=MQTTSN_DECODE_AS,
)

packets = []
for row in rows:
    row["frame"] = to_int(row["frame.number"])

    if not has_loopback_duplicate_fields(row):
        packets.append(row)

# The question asks for MQTT-SN messages received by clients from the local
# broker listening on UDP port 1885. Therefore the broker must be the sender:
# source port 1885, destination port is the client port.
broker_to_clients = []
client_to_broker = []

for packet in packets:
    if packet["udp.srcport"] == BROKER_PORT:
        broker_to_clients.append(packet)

    if packet["udp.dstport"] == BROKER_PORT:
        client_to_broker.append(packet)

print("CQ4")
print("---")
print("MQTT-SN messages received by clients from the local broker on UDP port 1885:")
print(f"Answer: {len(broker_to_clients)}")
print()
print("Direction check:")
print(f"- client -> broker messages: {len(client_to_broker)}")
print(f"- broker -> client messages: {len(broker_to_clients)}")
print()
print("Matched broker -> client MQTT-SN messages:")
if broker_to_clients:
    for packet in broker_to_clients:
        print(
            "- "
            f"frame={packet['frame']}, "
            f"{packet['ip.src']}:{packet['udp.srcport']} -> "
            f"{packet['ip.dst']}:{packet['udp.dstport']}, "
            f"type={packet['mqttsn.msg.type']}"
        )
else:
    print("- none")

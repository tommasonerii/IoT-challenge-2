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
LOCAL_IP = "127.0.0.1"
COAP_PORT = "5683"
RESOURCE = "/dining_room/temperature"

# CoAP numeric codes used by Wireshark.
TYPE_CON = 0
TYPE_ACK = 2
TYPE_RST = 3
METHOD_GET = 1
EMPTY = 0
CONTENT = 69  # 2.05 Content
OBSERVE_REGISTER = 0
OBSERVE_DEREGISTER = 1

FIELDS = [
    "frame.number",
    "frame.protocols",
    "ip.src",
    "udp.srcport",
    "ip.dst",
    "udp.dstport",
    "coap.type",
    "coap.code",
    "coap.mid",
    "coap.token",
    "coap.opt.observe",
    "coap.opt.uri_path_recon",
    "coap.response_first_in",
    "coap.retransmitted",
    "icmp.type",
    "icmp.code",
    "json.value.string",
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


def payload_parts(packet):
    # TShark exports the JSON strings as: dining,26.21,0127155907.
    # The resource name is the first item, the measured temperature is the
    # second item, and the application timestamp is the third item.
    payload = packet["json.value.string"]
    return payload.split(",") if payload else []


def payload_temperature(packet):
    try:
        parts = payload_parts(packet)
        if len(parts) < 3:
            return None
        return parts[1]
    except IndexError:
        return None


rows = read_tshark_fields(A_PCAP, "coap && !_ws.malformed", FIELDS)

# Convert only the fields that are easier to compare as numbers.
packets = []
for row in rows:
    row["frame"] = to_int(row["frame.number"])
    row["type"] = to_int(row["coap.type"])
    row["code"] = to_int(row["coap.code"])
    row["observe"] = to_int(row["coap.opt.observe"])
    packets.append(row)

# First find the Observe registration for /dining_room/temperature.
# This gives the client/server endpoints for the following notifications.
observe_request = None
for packet in packets:
    if (
        packet["type"] == TYPE_CON
        and packet["code"] == METHOD_GET
        and packet["observe"] == OBSERVE_REGISTER
        and packet["coap.opt.uri_path_recon"] == RESOURCE
        and packet["ip.dst"] == LOCAL_IP
        and packet["udp.dstport"] == COAP_PORT
    ):
        observe_request = packet
        break

notifications = []
initial_response = None
observe_termination = None
acks_by_mid = {}
icmp_port_unreachable_by_frame = {}

if observe_request:
    server_ip = observe_request["ip.dst"]
    server_port = observe_request["udp.dstport"]
    client_ip = observe_request["ip.src"]
    client_port = observe_request["udp.srcport"]

    for packet in packets:
        same_client_to_server = (
            packet["ip.src"] == client_ip
            and packet["udp.srcport"] == client_port
            and packet["ip.dst"] == server_ip
            and packet["udp.dstport"] == server_port
        )
        same_direction = (
            packet["ip.src"] == server_ip
            and packet["udp.srcport"] == server_port
            and packet["ip.dst"] == client_ip
            and packet["udp.dstport"] == client_port
        )

        if packet["frame"] <= observe_request["frame"]:
            continue

        explicit_deregister = (
            same_client_to_server
            and packet["code"] == METHOD_GET
            and packet["observe"] == OBSERVE_DEREGISTER
            and packet["coap.opt.uri_path_recon"] == RESOURCE
        )

        # A client-side RST rejects a notification and terminates the Observe
        # relation for this flow. An explicit GET with Observe=1 also cancels
        # the registration. Do not count packets after either event.
        if same_client_to_server and packet["type"] == TYPE_RST:
            observe_termination = packet
            break

        if explicit_deregister:
            observe_termination = packet
            break

        # CQ3 asks for notifications for this resource. Use CoAP fields first:
        # the Observe registration defines the relation, so notifications must
        # have the same token, the same resource path and the reversed endpoints.
        contains_temperature = payload_temperature(packet) is not None
        same_observe_token = packet["coap.token"] == observe_request["coap.token"]
        same_resource = packet["coap.opt.uri_path_recon"] == RESOURCE
        same_mid_as_registration = packet["coap.mid"] == observe_request["coap.mid"]

        if (
            same_direction
            and packet["code"] == CONTENT
            and same_observe_token
            and same_resource
            and same_mid_as_registration
        ):
            initial_response = packet
            continue

        # Use a broad filter first, then verify direction, token, resource,
        # payload and retransmission status before counting.
        # The first response to the Observe registration has the same MID as
        # the request. CQ3a asks for separate notifications, so only later
        # packets with the same token and a different MID are counted.
        if (
            same_direction
            and packet["code"] == CONTENT
            and same_observe_token
            and same_resource
            and not same_mid_as_registration
            and contains_temperature
            and not packet["coap.response_first_in"]
            and not packet["coap.retransmitted"]
            and not has_loopback_duplicate_fields(packet)
        ):
            notifications.append(packet)

# For CQ3b, a notification sent over the network but not successfully
# received/processed is useless traffic. In this trace those messages generate
# ICMP Port Unreachable; repeated payload values are tracked only as an
# optional secondary check.
for notification in notifications:
    for packet in packets:
        if (
            packet["frame"] > notification["frame"]
            and packet["ip.src"] == notification["ip.dst"]
            and packet["udp.srcport"] == notification["udp.dstport"]
            and packet["ip.dst"] == notification["ip.src"]
            and packet["udp.dstport"] == notification["udp.srcport"]
            and packet["type"] == TYPE_ACK
            and packet["code"] == EMPTY
            and packet["coap.mid"] == notification["coap.mid"]
        ):
            acks_by_mid[notification["coap.mid"]] = packet
            break

    for packet in packets:
        embedded_original_frame = packet.get("coap.response_first_in", "")
        if (
            packet["frame"] > notification["frame"]
            and packet.get("icmp.type") == "3"
            and packet.get("icmp.code") == "3"
            and embedded_original_frame == str(notification["frame"])
        ):
            icmp_port_unreachable_by_frame[notification["frame"]] = packet
            break

unacknowledged_notifications = []
unreachable_notifications = []
repeated_value_notifications = []
previous_temperature = None
for notification in notifications:
    temperature = payload_temperature(notification)
    notification["temperature"] = temperature

    if notification["coap.mid"] not in acks_by_mid:
        unacknowledged_notifications.append(notification)

    if notification["frame"] in icmp_port_unreachable_by_frame:
        unreachable_notifications.append(notification)

    if previous_temperature is not None and temperature == previous_temperature:
        repeated_value_notifications.append(notification)

    previous_temperature = temperature

print("CQ3a")
print("----")
print(f"Separate observe notifications containing values for {RESOURCE}, ignoring retransmissions:")
print(f"Answer: {len(notifications)}")
print()

if observe_request:
    print(
        "Observe registration: "
        f"frame={observe_request['frame']}, "
        f"token={observe_request['coap.token']}, "
        f"client={observe_request['ip.src']}:{observe_request['udp.srcport']}, "
        f"server={observe_request['ip.dst']}:{observe_request['udp.dstport']}"
    )
else:
    print("Observe registration: not found")

if initial_response:
    print(
        "Initial Observe response not counted: "
        f"frame={initial_response['frame']}, "
        f"MID={initial_response['coap.mid']}, "
        f"value={payload_temperature(initial_response)}"
    )

if observe_termination:
    print(
        "Observe termination: "
        f"frame={observe_termination['frame']}, "
        f"type={observe_termination['type']}, "
        f"MID={observe_termination['coap.mid']}"
    )

print()
print("Counted notifications:")
if notifications:
    for notification in notifications:
        token = notification["coap.token"] or "-"
        uri = notification["coap.opt.uri_path_recon"] or "-"
        print(
            "- "
            f"frame={notification['frame']}, "
            f"observe={notification['observe']}, "
            f"MID={notification['coap.mid']}, "
            f"token={token}, "
            f"uri={uri}, "
            f"value={notification['temperature']}, "
            f"ack_frame={acks_by_mid.get(notification['coap.mid'], {}).get('frame', '-')}, "
            f"icmp_unreachable_frame={icmp_port_unreachable_by_frame.get(notification['frame'], {}).get('frame', '-')}"
        )
else:
    print("- none")

print()
print("CQ3b")
print("----")
print("Useless counted notifications that generated ICMP Port Unreachable:")
print(f"Answer: {len(unreachable_notifications)}")
print()

if unreachable_notifications:
    for notification in unreachable_notifications:
        token = notification["coap.token"] or "-"
        icmp_frame = icmp_port_unreachable_by_frame[notification["frame"]]["frame"]
        print(
            "- "
            f"frame={notification['frame']}, "
            f"observe={notification['observe']}, "
            f"MID={notification['coap.mid']}, "
            f"token={token}, "
            f"value={notification['temperature']}, "
            f"icmp_unreachable_frame={icmp_frame}"
        )
else:
    print("- none")

print()
print("No-ACK secondary check:")
print(f"Notifications without a matching empty ACK: {len(unacknowledged_notifications)}")

print()
print("Repeated-value secondary check:")
print(f"Notifications with the same temperature as the previous counted one: {len(repeated_value_notifications)}")

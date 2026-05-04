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
COAP_ME_IP = "134.102.218.18"
COAP_PORT = "5683"

# CoAP numeric codes used by Wireshark.
TYPE_NON = 1
METHOD_GET = 1
METHOD_DELETE = 4
DELETE_SUCCESS = 66  # 2.02 Deleted
NOT_FOUND = 132  # 4.04 Not Found
COAP_SUCCESS_MIN = 64
COAP_SUCCESS_MAX = 96
COAP_CLIENT_ERROR_MIN = 128
COAP_CLIENT_ERROR_MAX = 160
COAP_SERVER_ERROR_MIN = 160
COAP_SERVER_ERROR_MAX = 192

FIELDS = [
    "frame.number",
    "ip.src",
    "udp.srcport",
    "ip.dst",
    "udp.dstport",
    "coap.type",
    "coap.code",
    "coap.mid",
    "coap.token",
    "coap.opt.uri_path_recon",
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


def is_success_response(code):
    return code is not None and COAP_SUCCESS_MIN <= code < COAP_SUCCESS_MAX


def is_client_error_response(code):
    return code is not None and COAP_CLIENT_ERROR_MIN <= code < COAP_CLIENT_ERROR_MAX


def is_server_error_response(code):
    return code is not None and COAP_SERVER_ERROR_MIN <= code < COAP_SERVER_ERROR_MAX


def is_error_response(code):
    return is_client_error_response(code) or is_server_error_response(code)


def is_non_empty_response(code):
    return is_success_response(code) or is_error_response(code)


def to_int(value):
    return int(value) if value else -1


def find_response_by_token(request, packets):
    # First filter candidate requests, then verify the matching response.
    # Do not trust packet counts from a broad filter alone.
    #
    # CQ1 uses NON requests. For NON messages the response has the same token,
    # but it can have a different MID, so MID is not a safe matching key here.
    #
    # Empty tokens are legal in CoAP, but matching on an empty token would make
    # unrelated messages look correlated. CQ1 only accepts non-empty tokens.
    if not request["coap.token"]:
        return None

    # Tokens can be reused later in the capture. To avoid a wrong match, use:
    # - same token
    # - NON response type
    # - response after the request
    # - reversed client/server IP addresses and UDP ports
    # - first matching response only
    for packet in packets:
        same_token = packet["coap.token"] == request["coap.token"]
        reversed_ips = packet["ip.src"] == request["ip.dst"] and packet["ip.dst"] == request["ip.src"]
        reversed_ports = (
            packet["udp.srcport"] == request["udp.dstport"]
            and packet["udp.dstport"] == request["udp.srcport"]
        )

        if (
            packet["frame"] > request["frame"]
            and packet["type"] == TYPE_NON
            and is_non_empty_response(packet["code"])
            and same_token
            and reversed_ips
            and reversed_ports
        ):
            return packet

    return None


def find_follow_up_get(delete_request, delete_response, packets):
    uri = delete_request["coap.opt.uri_path_recon"]
    if not uri:
        return None

    for packet in packets:
        if (
            packet["frame"] > delete_response["frame"]
            and packet["code"] == METHOD_GET
            and packet["ip.src"] == delete_request["ip.src"]
            and packet["ip.dst"] == delete_request["ip.dst"]
            and packet["udp.dstport"] == COAP_PORT
            and packet["coap.opt.uri_path_recon"] == uri
        ):
            return packet

    return None


rows = read_tshark_fields(A_PCAP, "coap && !_ws.malformed", FIELDS)

# Convert only the fields that are easier to compare as numbers.
packets = []
for row in rows:
    row["frame"] = to_int(row["frame.number"])
    row["type"] = to_int(row["coap.type"])
    row["code"] = to_int(row["coap.code"])
    packets.append(row)

# CQ1 starts from NON Confirmable DELETE requests directed to coap.me.
# The coap.me IP was resolved from the capture and the server uses UDP port 5683.
requests = []
for packet in packets:
    if (
        packet["type"] == TYPE_NON
        and packet["code"] == METHOD_DELETE
        and packet["ip.dst"] == COAP_ME_IP
        and packet["udp.dstport"] == COAP_PORT
    ):
        requests.append(packet)

successful = []
for request in requests:
    first_response = find_response_by_token(request, packets)

    # CQ1a: for a DELETE request, the proper successful response is 2.02
    # Deleted.
    if first_response and first_response["code"] == DELETE_SUCCESS:
        successful.append((request, first_response))

# CQ1b: the desired DELETE outcome is validated by a later GET to the same
# resource returning 4.04 Not Found.
desired_outcome = []
follow_up_checks = []
for request, response in successful:
    follow_up_get = find_follow_up_get(request, response, packets)
    follow_up_response = None
    if follow_up_get:
        follow_up_response = find_response_by_token(follow_up_get, packets)

    follow_up_checks.append((request, response, follow_up_get, follow_up_response))

    if follow_up_response and follow_up_response["code"] == NOT_FOUND:
        desired_outcome.append((request, response, follow_up_get, follow_up_response))

mids = []
for request, response in successful:
    mids.append(str(request["coap.mid"]))

print("CQ1a")
print("----")
print("NON Confirmable DELETE requests directed to coap.me with 2.02 Deleted response:")
print(f"Answer MIDs: {', '.join(mids) if mids else 'no matching MIDs'}")
print()

if successful:
    for request, response in successful:
        print(
            "- "
            f"MID={request['coap.mid']}, "
            f"request_frame={request['frame']}, "
            f"response_code={response['code']}"
        )
else:
    print("- none")

print()
print("CQ1b")
print("----")
print("Requests from CQ1a whose later GET to the same resource returns 4.04 Not Found:")
print(f"Answer: {len(desired_outcome)}")

print()
print("Matched requests and follow-up GET checks:")
if follow_up_checks:
    for request, response, follow_up_get, follow_up_response in follow_up_checks:
        if follow_up_get:
            get_frame = follow_up_get["frame"]
            get_token = follow_up_get["coap.token"]
        else:
            get_frame = "-"
            get_token = "-"

        if follow_up_response:
            get_response_frame = follow_up_response["frame"]
            get_response_code = follow_up_response["code"]
        else:
            get_response_frame = "-"
            get_response_code = "-"

        print(
            "- "
            f"request_frame={request['frame']}, "
            f"request_mid={request['coap.mid']}, "
            f"token={request['coap.token']}, "
            f"uri={request['coap.opt.uri_path_recon'] or '-'}, "
            f"response_frame={response['frame']}, "
            f"response_code={response['code']}, "
            f"response_mid={response['coap.mid']}, "
            f"follow_up_get_frame={get_frame}, "
            f"follow_up_get_token={get_token}, "
            f"follow_up_response_frame={get_response_frame}, "
            f"follow_up_response_code={get_response_code}"
        )
else:
    print("- none")

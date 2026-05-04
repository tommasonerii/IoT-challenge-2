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

# Verified in A.pcapng: CON POST/PUT traffic goes to 127.0.0.1:5683
# and to coap.me. CQ2 asks for the local server, so only 127.0.0.1:5683
# is used here.
LOCAL_IP = "127.0.0.1"
COAP_PORT = "5683"

# CoAP numeric codes used by Wireshark.
TYPE_CON = 0
METHOD_POST = 2
METHOD_PUT = 3
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
    # Start with candidate packets, then verify the request/response relation.
    # Do not count packets only because they match a broad display filter.
    #
    # CoAP CON responses can be piggybacked or separate:
    # - Piggybacked response: the ACK already contains the response code.
    #   It has the same token and the same MID as the request.
    # - Separate response: the server can first send an Empty ACK with code 0
    #   and the same MID, then later send the real response with the same token
    #   and a different MID.
    #
    # This function ignores Empty ACKs by requiring a non-empty response code
    # before returning a packet as the real response. This prevents losing the
    # later error response in a separate-response exchange.
    #
    # Tokens can be reused or even empty, so token is not enough by itself.
    # Use reversed endpoints, and use the MID when the response is piggybacked.
    for packet in packets:
        # Empty ACK: the server confirms the CON request but has not sent the
        # real response yet. Skip it and keep looking for the separate response.
        if packet["code"] == 0:
            continue

        same_token = packet["coap.token"] == request["coap.token"]
        same_mid = packet["coap.mid"] == request["coap.mid"]
        reversed_ips = packet["ip.src"] == request["ip.dst"] and packet["ip.dst"] == request["ip.src"]
        reversed_ports = (
            packet["udp.srcport"] == request["udp.dstport"]
            and packet["udp.dstport"] == request["udp.srcport"]
        )
        is_later_response = (
            packet["frame"] > request["frame"]
            and is_non_empty_response(packet["code"])
        )

        if is_later_response and same_token and same_mid and reversed_ips and reversed_ports:
            return packet

        # Separate response: same non-empty token and reversed endpoints.
        # Do not match separate responses with an empty token by token alone.
        if is_later_response and request["coap.token"] and same_token and reversed_ips and reversed_ports:
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

# Keep only CON POST/PUT requests sent to the local CoAP server.
# The question asks for requests received by resources in the local server,
# so public coap.me requests are intentionally excluded.
requests = []
for packet in packets:
    is_post_or_put = packet["code"] == METHOD_POST or packet["code"] == METHOD_PUT
    is_local_server = packet["ip.dst"] == LOCAL_IP and packet["udp.dstport"] == COAP_PORT

    if packet["type"] == TYPE_CON and is_post_or_put and is_local_server:
        requests.append(packet)

unsuccessful_requests = []
seen_requests = set()

for request in requests:
    response = find_response_by_token(request, packets)

    # Count the request only if the matched response explicitly says it failed.
    if response and is_error_response(response["code"]):
        resource = request["coap.opt.uri_path_recon"] or "/"
        method = "POST" if request["code"] == METHOD_POST else "PUT"

        # This avoids counting the same logical CON request twice if it appears
        # again as a retransmission. Count different requests, not different
        # error codes.
        request_key = (
            method,
            resource,
            request["coap.mid"],
            request["coap.token"],
            request["ip.src"],
            request["udp.srcport"],
            request["ip.dst"],
            request["udp.dstport"],
        )

        if request_key not in seen_requests:
            seen_requests.add(request_key)
            unsuccessful_requests.append((resource, method, request, response))

# Count unsuccessful POST and PUT requests for each resource.
counts = {}
for resource, method, request, response in unsuccessful_requests:
    if resource not in counts:
        counts[resource] = {"POST": 0, "PUT": 0}

    counts[resource][method] += 1

matching_resources = []
for resource, values in counts.items():
    post_count = values["POST"]
    put_count = values["PUT"]

    if post_count == put_count and post_count > 0:
        matching_resources.append(resource)

matching_resources.sort()

print("CQ2")
print("---")
print("Resources with the same number of unsuccessful CON POST and PUT requests:")
print(f"Answer: {len(matching_resources)}")
print()

if matching_resources:
    for resource in matching_resources:
        post_count = counts[resource]["POST"]
        put_count = counts[resource]["PUT"]
        print(f"- {resource}: POST={post_count}, PUT={put_count}")
else:
    print("- none")

print()
print("Matched unsuccessful requests:")
if unsuccessful_requests:
    for resource, method, request, response in unsuccessful_requests:
        print(
            "- "
            f"resource={resource}, "
            f"method={method}, "
            f"request_frame={request['frame']}, "
            f"request_mid={request['coap.mid']}, "
            f"response_frame={response['frame']}, "
            f"response_code={response['code']}"
        )
else:
    print("- none")

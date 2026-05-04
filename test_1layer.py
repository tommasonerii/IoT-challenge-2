import sys
sys.path.append(r'C:\Users\Tommaso\Code\Iot2\part1\scripts')
from cq8_compare_local_broker import find_pcap, local_publish_messages

count = 0
for message in local_publish_messages(find_pcap('A.pcapng')):
    if message['layers'] == 1:
        count += 1
        print(
            'Frame:', message['frame.number'],
            'Topic:', message['mqtt.topic'],
            'Src:', message['ip.src'] or message['ipv6.src'],
            'Dst:', message['ip.dst'] or message['ipv6.dst'],
            message['tcp.dstport'],
        )

print('Count:', count)

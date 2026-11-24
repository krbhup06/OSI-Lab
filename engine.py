
from protocols import PROTOCOLS

def simulate_encapsulation(protocol_name: str):
    proto = PROTOCOLS[protocol_name]

    # application -> raw data of user
    l7 = f"[L7 Data: {proto['payload']}]"

    # presentation -> encryption
    l6 = f"[L6 UTF-8] {l7}"

    # session -> session id
    l5 = f"[L5 Session_ID] {l6}"

    # transport -> add port and Transport protocol(TCP/UDP)
    l4 = f"[L4 {proto['transport']} Port:{proto['port']}] {l5}"

    # network -> IP address
    l3 = f"[L3 IP:< DestinationIP , SourceIP >] {l4}"

    # datalink -> MAC address
    l2 = f"[L2 MAC:<Changes as per switch which it forwards>] {l3}"

    # physical -> bits
    bits = " ".join(format(ord(char), "08b") for char in l2[:10]) + " ..."
    l1 = f"[L1 bits] {bits}"

    return [
        ("Layer7", l7),
        ("Layer6", l6),
        ("Layer5", l5),
        ("Layer4", l4),
        ("Layer3", l3),
        ("Layer2", l2),
        ("Layer1", l1)
    ]

if __name__=="__main__":
    for layer_name, packet_state in simulate_encapsulation("DNS"):
        print(f"{layer_name} -> {packet_state}")
import socket

# CRC-24 function for ADS-B messages
def crc24(data):
    crc = 0
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1FFF409
    return crc & 0xFFFFFF


# Example of a live ADS-B message
def test_crc():
    msg = "8DADB72399955B0DB064A8BADE7D"

    data = bytes.fromhex(msg[:22])
    expected_crc = msg[22:]

    result = crc24(data)
    print(f"Got:            {result:06X}")
    print(f"Expected:       {expected_crc}")
    print(f"Match:          {expected_crc.upper() == f'{result:06X}'}")

# TCP connect and send
def connect(host, port):
    s = socket.socket()
    s.settimeout(5)

    try:
        s.connect((host, port))
        print(f"[+] Connected to {host}:{port}")
        return s
    except Exception as e:
        print(f"[-] Failed to connect to {host}:{port} - {e}")
        return None

def send(sock, msg):
    msgEncoded = f"*{msg};\r\n".encode()
    sock.sendall(msgEncoded)

# Encode ICAO
def encode_icao(icao):
    int(icao, 16)
    



# Build messages

# Ghost aircraft class

# main
if __name__ == "__main__":
    test_crc()

    sock = connect('127.0.0.1', 30001)
    if sock:
        send(sock,"8DADB72399955B0DB064A8BADE7D")


    input()
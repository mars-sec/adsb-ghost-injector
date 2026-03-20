import socket
import time

#ADS-B header info

downlinkFormat = 17 # Extended Squitter
capability = 5 # Level 2 transponder

header = bytes([(downlinkFormat << 3) | capability]) # capability occupies the bottom 3 bits of the first byte

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

# Append CRC to message
def append_crc(msg):
    crc = crc24(msg)
    byte1 = crc >> 16 & 0xFF
    byte2 = crc >> 8 & 0xFF
    byte3 = crc & 0xFF
    return msg + bytes([byte1, byte2, byte3])
    


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
    icaoInt = int(icao, 16) & 0xFFFFFF
    byte1 = (icaoInt >> 16) & 0xFF
    byte2 = (icaoInt >> 8) & 0xFF
    byte3 = icaoInt & 0xFF
    return bytes([byte1, byte2, byte3])

# Build messages
# Callsign messages where TC=4

def build_callsign_message(icao, callsign):
    tc = 4
    category = 0
    
    characterSet = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?"
    callsign = callsign.upper().ljust(8)[:8]
    encoded = 0
    for char in callsign:
        index = characterSet.find(char)
        if index == -1:
            index = 32
        encoded = (encoded << 6) | index

    tc = tc << 51
    category = category << 48
    me = (tc | category | encoded)
    me_bytes = me.to_bytes(7, 'big')
    
    callsign_msg = header + encode_icao(icao) + me_bytes
    callsign_msg_with_crc = append_crc(callsign_msg)

    return callsign_msg_with_crc.hex().upper() 


# Altitude encoding
# This has to fit into 13 bits, so we use the 25ft resolution encoding for our altitude.
# The formula is: N = (altitude + 1000) / 25
# This means we can encode altitudes from -1000ft to 12675ft. 
# For higher altitudes, we would need to use the 100ft resolution encoding, which has a different formula and is less precise. I have no need for this, so I will stick to the 25ft encoding.

def encode_altitude(altitude):
    n = int((altitude + 1000) // 25)
    if n < 0 or n > 0x1FFF:
        raise ValueError("Altitude out of range for 25ft encoding")
    qBit = 1 # Set the Q bit to indicate 25ft encoding, 0 would indicate Gillham encoding
    upper = (n & 0x7F0) << 1 # Upper 7 bits of N go into bits 1-7 of the altitude field
    qBitShifted = qBit << 4 # Q bit goes into bit 4 of the altitude field
    lower = (n & 0x00F) << 1 # Lower 4 bits of N go into bits 5-8 of the altitude field
    return (upper | qBitShifted | lower) & 0x1FFF # Return the final 13-bit altitude encoding



# Ghost aircraft class

# main
if __name__ == "__main__":
    test_crc()
    msg = build_callsign_message("AABBCC", "MARSEC")
    print(f"Generated message: {msg}")
    print(f"Length: {len(msg)} characters, {len(msg)//2} bytes")

    sock = connect('127.0.0.1', 30001)
    if sock:
        print("[+] Sending message...")
        for i in range(5):
            send(sock,msg)
            print(f"[+] Message sent: {i+1}/30")
            time.sleep(1)
    
        print("Attempting altitude encoding test...")
        print(f"Encoded altitude for 5000ft: {encode_altitude(5000):013b} (binary), {encode_altitude(5000)} (decimal)")

    input()
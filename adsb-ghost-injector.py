import socket
import time
import math


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
    lower = (n & 0x00F) # Lower 4 bits of N go into bits 5-8 of the altitude field
    return (upper | qBitShifted | lower) & 0x1FFF # Return the final 13-bit altitude encoding


# CPR encoding for position messages (TC=9 and TC=11) is more complex and requires latitude and longitude to be encoded into a 17-bit format.
# CPR encoding is a bit more complex and is used for position messages (TC=9 and TC=11). It involves encoding latitude and longitude into a 17-bit format, which allows for efficient transmission of position data. 
# The encoding process includes calculating the latitude and longitude indices based on the current position and the reference position, 
# and then combining these indices into a single 17-bit value. This value is then included in the message payload along with other necessary information 
# such as altitude and velocity. 
# exploit.org has a great writeup on CPR encoding and ADS-B spoofing, which can be found here: https://blog.exploit.org/tag/ads-b/. Huge thanks to STERVA who write that up and provided a lot of the foundational knowledge for this project.
# I will be implementing CPR encoding based on the information provided in that writeup, as well as the ADS-B specifications.

# Also used throughout this function was https://mode-s.org/1090mhz/, which is an invaluable resource for understanding the technical details of ADS-B message formats and encoding. 
# The actual ADS-B specifications can be found in the DO-260B document, which is available online and provides detailed information on message formats, encoding schemes, and 
# other technical aspects of ADS-B, but is much more dry than the linked resources.

def encode_cpr(lat, lon, is_odd):
    d_lat = 360.0 / (60 - (1 if is_odd else 0))
    lat_cpr = int((lat / d_lat - math.floor(lat / d_lat)) * 131072 + 0.5) % 131072 # These might seem like magic numbers, but they are derived from the CPR encoding process. 131072 is 2^17, which is the number of possible values for the 17-bit encoding.
    if abs(lat) >= 87.0: # For latitudes above 87 degrees, the number of longitude zones is 1, meaning longitude is not encoded and can be set to 0.
        nl = 1
    else:
        nl = math.floor(2 * math.pi / math.acos(1 - (1 - math.cos(math.pi / 30)) / math.cos(math.pi * lat /180) ** 2)) # This is a fixed formula from the ADS-B specifications to calculate the number of longitude zones based on latitude.
        
    n = max(1, nl - (1 if is_odd else 0))
    d_lon = 360.0 / n
    lon_cpr = int((lon / d_lon - math.floor(lon / d_lon)) * 131072 + 0.5) % 131072
    return lat_cpr, lon_cpr

# Build airborne position message (TC=11)
def airborne_position_message(icao, altitude, lat, lon, is_odd):
    tc = 11
    surveillanceStatus = 0 # No condition change
    nicSupplement = 0 # No supplementary information
    altitude = encode_altitude(altitude)
    timeFlag = 0 # 0 being not synchronized to UTC, 1 being synchronized to UTC.
    fFlag = 1 if is_odd else 0 # F flag is set to 1 for odd frames and 0 for even frames
    lat_cpr, lon_cpr = encode_cpr(lat, lon, is_odd)

    # Time to asesmble the message. The payload for TC=11 is 56 bits, which we will construct as follows:
    me = (tc << 52) | (surveillanceStatus << 50) | (nicSupplement << 49) | (altitude << 36) | (timeFlag << 35) | (fFlag << 34) | (lat_cpr << 17) | lon_cpr
    me_bytes = me.to_bytes(7, 'big')
    position_msg = header + encode_icao(icao) + me_bytes
    position_msg_with_crc = append_crc(position_msg)
    return position_msg_with_crc.hex().upper()



# Ghost aircraft class

# main
if __name__ == "__main__":
    test_crc()
    callsignMsg = build_callsign_message("AABBCC", "MARSEC")
    positionMsgOdd = airborne_position_message("AABBCC", 10000, 40.6966, -80.0122, is_odd=True)
    positionMsgEven = airborne_position_message("AABBCC", 10000, 40.6966, -80.0122, is_odd=False)


    sock = connect('127.0.0.1', 30001)
    if sock:
        print("[+] Sending message...")
        for i in range(30):
            send(sock,positionMsgEven)
            print(f"[+] Position Message (Even) sent: {i+1}/5")
            send(sock,positionMsgOdd)
            print(f"[+] Position Message (Odd) sent: {i+1}/5")
            send(sock,callsignMsg)
            print(f"[+] Callsign Message sent: {i+1}/5")
            time.sleep(1)
    


    input()
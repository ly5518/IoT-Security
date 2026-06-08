import hashlib

firmware_data = "新能源充电桩固件V1.0".encode("utf-8")

firmware_hash = hashlib.sha256(firmware_data).hexdigest()

print("固件SHA256值：")
print(firmware_hash)

local_hash = firmware_hash

if firmware_hash == local_hash:

    print("\n固件完整性校验成功")

else:

    print("\n固件被篡改")
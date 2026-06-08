import json
import hashlib
import time
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
import base64
# 用户数据库（扫码认证）
USER_DB = {
    "20260530": {
        "name": "小罗",
    },
    "20260531": {
        "name": "燕子",
    }
}

print("========== 用户身份认证 ==========")

user_id = input("请输入用户ID(模拟扫码)：")

if user_id not in USER_DB:
    print("用户认证失败")
    exit()

print("用户认证成功")
print("用户姓名：", USER_DB[user_id]["name"])

print("========== 开始充电 ==========")
status = "charging"
print("充电状态：", status)
print("正在充电...")
time.sleep(3)
status = "finished"
print("充电完成")

# MQTT配置
BROKER = "localhost"
PORT = 1883

# 设备ID
DEVICE_ID = "ev_charge_A01"
# 测试非法设备
# DEVICE_ID = "hacker001"

# Topic权限隔离
TOPIC = f"ev/{DEVICE_ID}"
# 测试非法Topic
# TOPIC = "ev/hacker_device"
# AES密钥
KEY = b"1234567890abcdef"

# Token生成
token = hashlib.sha256(DEVICE_ID.encode()).hexdigest()
# 测试非法Token
# token = hashlib.sha256("hacker001".encode()).hexdigest()

print("设备Token：")
print(token)

# 模拟充电数据

data = {
    "user_id": user_id,
    "device_id": DEVICE_ID,
    "status": status,
    "energy": 18.5,
    "price": 1.2,
    "amount": 22.2,
    "power": "45kwh",
    "voltage": "380V",
    "current": "32A",
    "user": "18229889540",
    "token": token,
    "timestamp": time.time()
    # "timestamp": time.time() - 100
}

# # 数据完整性校验
# 正常生成
message_hash = hashlib.sha256(json.dumps(data).encode()).hexdigest()
data["hash"] = message_hash
#攻击模拟
# data["amount"] = 999   
print("\n发送数据：", data)
# AES加密
def encrypt_data(data):

    cipher = AES.new(KEY, AES.MODE_EAX)

    plaintext = json.dumps(data).encode()

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    encrypted = {

        "nonce": base64.b64encode(cipher.nonce).decode(),

        "ciphertext": base64.b64encode(ciphertext).decode(),

        "tag": base64.b64encode(tag).decode()
    }

    return json.dumps(encrypted)

encrypted_message = encrypt_data(data)

print("\nAES加密后的数据：")
print(encrypted_message)

# MQTT发送
# client = mqtt.Client()
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.connect(BROKER, PORT, 60)

client.publish(TOPIC, encrypted_message)

print("\n数据已发送到Topic：", TOPIC)
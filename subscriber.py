import json
import hashlib
import time
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
import base64
import csv
import os
BROKER = "localhost"
PORT = 1883

# Topic权限隔离
TOPIC = "ev/#"

KEY = b"1234567890abcdef"

# 白名单
WHITE_LIST = ["ev_charge_A01"]

# 黑名单
BLACK_LIST = []

# 异常次数
login_fail_count = {}

# 在线设备
online_devices = []

# 用户数据库（RBAC）
USERS = {

    "admin": {
        "password": "123456",
        "role": "admin"
    },

    "user": {
        "password": "654321",
        "role": "user"
    }
}

# AES解密
def decrypt_data(encrypted_data):

    data = json.loads(encrypted_data)

    nonce = base64.b64decode(data["nonce"])

    ciphertext = base64.b64decode(data["ciphertext"])

    tag = base64.b64decode(data["tag"])

    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return json.loads(plaintext.decode())

# 手机号脱敏
def mask_phone(phone):

    return phone[:3] + "****" + phone[-4:]
def save_charge_record(data):

    filename = "charge_record.csv"

    file_exists = os.path.exists(filename)

    with open(
        filename,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        if not file_exists:

            writer.writerow([
                "设备ID",
                "状态",
                "充电量(kWh)",
                "电价(元)",
                "金额(元)",
                "用户",
                "时间"
            ])

        writer.writerow([
            data["device_id"],
            data["status"],
            data["energy"],
            data["price"],
            data["amount"],
            mask_phone(data["user"]),
            time.ctime()
        ])

def security_check(msg, result, device_id):
    print("\n========== 安全验证 ==========")

    # 1 Topic权限隔离
    expected_topic = f"ev/{device_id}"
    if msg.topic != expected_topic:
        print("Topic权限非法访问")
        return False
    print("Topic权限校验成功")

    # 2 黑名单检测
    if device_id in BLACK_LIST:
        print("设备已被封禁")
        return False

    # 3 白名单检测
    if device_id not in WHITE_LIST:
        print("非法设备，拒绝接入")

        login_fail_count[device_id] = login_fail_count.get(device_id, 0) + 1
        count = login_fail_count[device_id]

        print("异常登录次数：", count)

        if count >= 3:
            BLACK_LIST.append(device_id)
            print("触发入侵报警：已加入黑名单")

        return False

    print("设备身份合法，继续验证...")

    # 4 Token认证
    local_token = hashlib.sha256(device_id.encode()).hexdigest()
    if local_token != result["token"]:
        print("Token校验失败")
        return False
    print("Token校验成功")

    # 5 数据完整性（关键修复点）
    temp = result.copy()
    temp.pop("hash", None)

    local_hash = hashlib.sha256(json.dumps(temp).encode()).hexdigest()

    if local_hash != result.get("hash"):
        print("数据被篡改")
        return False
    print("数据完整性校验成功")

    # 6 时间戳防重放
    if time.time() - result["timestamp"] > 30:
        print("数据超时（疑似重放攻击）")
        return False
    print("时间戳校验正常")

    return True
def business_process(result):

    print("\n========== 业务信息 ==========")

    print("用户ID：", result["user_id"])
    print("设备ID：", result["device_id"])
    print("充电状态：", result["status"])
    print("累计充电量：", result["energy"], "kWh")
    print("电价：", result["price"], "元/kWh")
    print("计费金额：", result["amount"], "元")


    print("\n========== 订单结算 ==========")

    order_id = "ORD" + str(int(time.time()))

    print("订单号：", order_id)
    print("用户ID：", result["user_id"])
    print("充电量：", result["energy"], "kWh")
    print("应付金额：", result["amount"], "元")
    print("支付状态：支付成功")

    save_charge_record(result)

    print("充电记录已保存")
    print("\n订单状态：已完成")
    print("充电业务完成")
    
def rbac_control():

    print("\n========== RBAC权限控制 ==========")

    username = input("请输入管理员用户名：")
    password = input("请输入管理员密码：")

    if username in USERS and USERS[username]["password"] == password:

        role = USERS[username]["role"]

        print("\n登录成功")
        print("当前角色：", role)

        if role == "admin":

            print("\n管理员权限：")
            print("√ 允许远程启动充电")
            print("√ 允许停止充电")
            print("√ 允许查看充电信息")
            print("√ 允许管理设备")

            with open("admin_log.txt", "a", encoding="utf-8") as f:
                f.write(f"{time.ctime()} 管理员 {username} 登录系统\n")

            print("管理员操作日志已记录")

        else:

            print("\n普通用户权限：")
            print("√ 允许查看充电信息")
            print("× 禁止远程启动充电")
            print("× 禁止管理设备")

    else:
        print("\n用户名或密码错误")   
        
 # MQTT消息回调        
def on_message(client, userdata, msg):

    print("\n========== 接收到MQTT消息 ==========")
    print("当前Topic：", msg.topic)

    try:
        result = decrypt_data(msg.payload.decode())
    except Exception as e:
        print("AES解密失败")
        print("错误原因：", e)
        return

    print("\n解密后的数据：")
    print(result)
    device_id = result["device_id"]

    # 安全层（入口控制）
    if not security_check(msg, result, device_id):
        return

    # 在线状态（辅助）
    if device_id not in online_devices:
        online_devices.append(device_id)
        print("设备首次上线")

    # 隐私保护
    print("脱敏手机号：", mask_phone(result["user"]))

    # 功率检测
    power = result["power"]
    num = int(power.replace("kwh", ""))

    if num > 100:
        print("异常充电功率（警告，但不中断业务）")
    else:
        print("充电功率正常")

    # 业务层
    business_process(result)

    # RBAC（最后执行）
    rbac_control()    
    
# MQTT监听
# client = mqtt.Client()
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

client.on_message = on_message

client.connect(BROKER, PORT, 60)

client.subscribe(TOPIC)

print("MQTT服务器监听中...")

client.loop_forever()

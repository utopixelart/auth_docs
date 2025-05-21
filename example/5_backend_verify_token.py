#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
后端验证访问令牌的示例脚本
模拟后端应用验证从前端接收到的访问令牌
使用App Key和Secret Key调用Utopixel的令牌验证API
"""

import json
import requests
import hmac
import hashlib
import time
import os

###########################################
#            配置部分 - 修改这里            #
###########################################

# Utopixel API基础URL
UTOPIXEL_BASE_URL = "https://api.utopixel.art/api/user"

# 令牌验证端点
VERIFY_TOKEN_ENDPOINT = f"{UTOPIXEL_BASE_URL}/auth/verify_token"

# 您的App Key和Secret Key，从Utopixel管理员处获取
APP_KEY = "your_app_key"  # 替换为您的App Key
SECRET_KEY = "your_secret_key"  # 替换为您的Secret Key

# 模拟从前端接收到的访问令牌 (实际应用中，这将从前端请求中获取)
# 这里我们从本地文件中获取以便演示，实际应用中通常从HTTP请求头获取
TOKEN_FILE = "utopixel_tokens.json"  # 令牌文件路径

###########################################
#               脚本逻辑                  #
###########################################

print("===== 后端令牌验证示例 =====\n")

# 步骤1: 模拟获取前端传来的访问令牌
print("步骤1: 获取访问令牌...")
print("* 注意: 在实际的后端应用中，访问令牌通常从HTTP请求的Authorization头获取")
print("* 本示例从文件中读取令牌，仅作演示用途")

# 从文件读取令牌 (仅为演示)
access_token = None
try:
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r', encoding='utf-8') as f:
            token_data = json.load(f)
            access_token = token_data.get('access_token')
        print(f"* 从文件 {TOKEN_FILE} 读取了访问令牌")
    
    if not access_token:
        # 如果没有找到文件或文件中没有令牌，使用一个演示令牌
        access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        print("* 未找到令牌文件，使用示例令牌进行演示")
        
    print(f"* 访问令牌: {access_token[:15]}... (已截断)")
    
except Exception as e:
    print(f"* 警告: 读取令牌文件失败 - {str(e)}")
    access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    print("* 使用示例令牌进行演示")

# 步骤2: 准备验证请求
print("\n步骤2: 准备验证请求...")
print(f"* 验证端点: {VERIFY_TOKEN_ENDPOINT}")
print(f"* 使用App Key: {APP_KEY}")

# 准备请求体
request_body = {
    "token": access_token
}
request_body_json = json.dumps(request_body)

# 步骤3: 生成请求签名
print("\n步骤3: 生成请求签名...")
# 获取当前时间戳
timestamp = str(int(time.time()))
print(f"* 时间戳: {timestamp}")

# 构建签名字符串 (格式: HTTP方法\n路径\n时间戳\n请求体)
path = VERIFY_TOKEN_ENDPOINT.replace(UTOPIXEL_BASE_URL, "")  # 提取路径部分
signature_string = f"POST\n{path}\n{timestamp}\n{request_body_json}"
print(f"* 签名字符串: {signature_string}")

# 使用HMAC-SHA256算法和Secret Key生成签名
def generate_hmac_sha256(data, key):
    h = hmac.new(key.encode(), data.encode(), hashlib.sha256)
    return h.hexdigest()

signature = generate_hmac_sha256(signature_string, SECRET_KEY)
print(f"* 生成的签名: {signature[:15]}... (已截断)")

# 步骤4: 准备请求头
print("\n步骤4: 准备请求头...")
headers = {
    "Content-Type": "application/json",
    "X-App-Key": APP_KEY,
    "X-Timestamp": timestamp,
    "X-Signature": signature
}

print("* 请求头:")
for key, value in headers.items():
    if key == "X-Signature":
        print(f"  - {key}: {value[:15]}... (已截断)")
    else:
        print(f"  - {key}: {value}")

# 步骤5: 发送验证请求
print("\n步骤5: 发送验证请求...")
print("* 注意: 在这个示例中，我们将模拟API调用，因为实际的API可能不存在或需要有效的凭证")

try:
    # 模拟API调用
    should_simulate = True
    
    if not should_simulate:
        # 实际API调用 (取消注释以进行实际调用)
        response = requests.post(
            VERIFY_TOKEN_ENDPOINT,
            headers=headers,
            data=request_body_json
        )
        
        print(f"* 请求发送成功 (HTTP状态码: {response.status_code})")
        if response.status_code == 200:
            verification_result = response.json()
        else:
            print(f"* 错误: 服务器返回状态码 {response.status_code}")
            print(f"* 响应内容: {response.text}")
            verification_result = {"error": "验证失败", "status_code": response.status_code}
    else:
        # 模拟响应
        print("* 这是一个模拟的API调用")
        print("* 在实际应用中，您需要使用真实的App Key和Secret Key发送请求")
        
        # 模拟验证结果
        verification_result = {
            "is_valid": True,
            "user_id": "user_123456",
            "username": "demo_user",
            "expires_at": int(time.time()) + 3600,  # 假设令牌还有1小时有效期
            "scopes": [],
            "status": {
                "code": 0,
                "message": "Success"
            }
        }
        
        print("* 模拟响应生成成功")
    
except Exception as e:
    print(f"* 错误: 请求失败 - {str(e)}")
    verification_result = {
        "status": {
            "code": 1,
            "message": str(e)
        }
    }

# 步骤6: 处理验证结果
print("\n步骤6: 处理验证结果...")
print("\n===== 验证结果 =====")
print(json.dumps(verification_result, indent=2, ensure_ascii=False))

# 检查令牌是否有效
status_code = verification_result.get('status', {}).get('code')
is_valid = verification_result.get('is_valid', False)

if status_code == 0 and is_valid:
    user_id = verification_result.get('user_id', '')
    username = verification_result.get('username', '')
    print("\n* 令牌验证成功!")
    print(f"* 用户ID: {user_id}")
    print(f"* 用户名: {username}")
    print("* 您的后端应用现在可以继续处理请求，因为令牌是有效的")
else:
    error_message = verification_result.get('status', {}).get('message', '未知错误')
    print("\n* 令牌验证失败!")
    print(f"* 错误: {error_message}")
    print("* 您的后端应用应该拒绝这个请求")

print("\n===== 总结 =====")
print("这个脚本演示了后端应用如何验证从前端接收到的访问令牌:")
print("1. 从前端请求中提取访问令牌（示例中从文件读取）")
print("2. 准备向Utopixel的令牌验证API发送请求")
print("3. 使用App Key和Secret Key生成请求签名")
print("4. 将签名添加到请求头中")
print("5. 发送验证请求并接收响应")
print("6. 根据验证结果决定是否处理请求")

print("\n===== 下一步 =====")
print("您已经了解了Utopixel认证服务的完整流程！")
print("现在您可以将这些知识应用到您的实际应用程序中了。") 
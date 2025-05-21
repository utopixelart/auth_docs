#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
使用访问令牌调用API的示例脚本
读取之前获取的令牌，向受保护的API发起请求
"""

import json
import requests
import os
import time
from datetime import datetime

###########################################
#            配置部分 - 修改这里            #
###########################################

# 令牌文件路径
TOKEN_FILE = "utopixel_tokens.json"

# 示例API端点 - 这里使用一个假设的端点，您需要替换为实际的API端点
# 例如您自己的API，或者Utopixel提供的API
API_ENDPOINT = "https://your-backend-api.com/api/protected-resource"

###########################################
#               脚本逻辑                  #
###########################################

print("===== 使用访问令牌调用API示例 =====\n")

# 步骤1: 读取令牌文件
print("步骤1: 读取保存的令牌...")
if not os.path.exists(TOKEN_FILE):
    print(f"* 错误: 令牌文件 {TOKEN_FILE} 不存在")
    print("* 请先运行 2_token.py 获取访问令牌")
    exit(1)

try:
    with open(TOKEN_FILE, 'r', encoding='utf-8') as f:
        token_data = json.load(f)
    print("* 令牌文件读取成功")
except Exception as e:
    print(f"* 错误: 无法读取令牌文件 - {str(e)}")
    exit(1)

# 步骤2: 检查令牌是否有效
print("\n步骤2: 检查令牌有效性...")
access_token = token_data.get('access_token')
token_type = token_data.get('token_type', 'Bearer')
expires_at = token_data.get('expires_at', 0)

if not access_token:
    print("* 错误: 令牌文件中没有访问令牌")
    exit(1)

current_time = time.time()
if current_time > expires_at:
    print("* 警告: 访问令牌已过期!")
    print(f"* 过期时间: {datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')}")
    print("* 您可以运行 4_refresh.py 刷新令牌")
    
    # 询问是否继续使用过期令牌
    continue_anyway = input("\n令牌已过期，是否仍然继续? (y/n): ").strip().lower()
    if continue_anyway != 'y':
        print("已取消请求。")
        exit(0)
    print("* 继续使用过期令牌...")
else:
    remaining_time = int(expires_at - current_time)
    print(f"* 访问令牌有效，还剩 {remaining_time} 秒过期")
    print(f"* 过期时间: {datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')}")

# 步骤3: 准备API请求
print("\n步骤3: 准备API请求...")
print(f"* 目标API: {API_ENDPOINT}")
print(f"* 使用令牌: {access_token[:15]}... (已截断)")

headers = {
    "Authorization": f"{token_type} {access_token}",
    "Content-Type": "application/json"
}

print("* 请求头已设置:")
for key, value in headers.items():
    # 对Authorization头的值进行部分隐藏
    if key == "Authorization":
        parts = value.split()
        if len(parts) > 1:
            value = f"{parts[0]} {parts[1][:15]}..."
    print(f"  - {key}: {value}")

# 步骤4: 发送API请求
print("\n步骤4: 发送API请求...")
print("* 注意: 此示例尝试请求一个示例API。在实际使用中，您需要将API_ENDPOINT替换为真实的API端点。")

try:
    # 这里我们将使用一个条件来模拟API调用，因为实际的API可能不存在
    if "your-backend-api.com" in API_ENDPOINT:
        print("* 这是一个模拟的API调用 (因为使用了示例URL)")
        print("* 在实际应用中，您应该修改顶部的API_ENDPOINT配置为真实的API地址")
        
        # 模拟的API响应
        api_response = {
            "success": True,
            "data": {
                "user_id": token_data.get('user', {}).get('id', 'unknown'),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "status": {
                "code": 0,
                "message": "Success"
            }
        }
    else:
        # 实际API调用
        response = requests.get(API_ENDPOINT, headers=headers)
        print(f"* 请求发送成功 (HTTP状态码: {response.status_code})")
        api_response = response.json()
        
    print("* API响应成功解析")
    
except Exception as e:
    print(f"* 错误: API请求失败 - {str(e)}")
    exit(1)

# 步骤5: 显示API响应
print("\n步骤5: 显示API响应...")
print("\n===== API响应内容 =====")
print(json.dumps(api_response, indent=2, ensure_ascii=False))

# 检查响应状态
status = api_response.get('status', {})
status_code = status.get('code')
if status_code == 0:
    print("\n* API请求成功!")
    if 'data' in api_response:
        print("* 返回数据概览:")
        for key, value in api_response['data'].items():
            print(f"  - {key}: {value}")
else:
    print("\n* API请求返回错误状态!")
    print(f"* 错误码: {status_code}")
    print(f"* 错误信息: {status.get('message', '未知错误')}")

print("\n===== 总结 =====")
print("1. 成功从文件读取了访问令牌")
print("2. 使用访问令牌构建了带有Authorization头的请求")
print("3. 向API发送了请求并接收到响应")
print("\n在实际应用中，您可以根据业务需求处理API返回的数据，或者调用不同的API端点。")

print("\n===== 下一步 =====")
print("如果令牌已过期，运行 4_refresh.py 获取新的访问令牌") 
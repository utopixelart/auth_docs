#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
使用授权码获取访问令牌和刷新令牌的示例脚本
在用户完成授权后使用获取到的授权码
"""

import json
import requests
import time
from datetime import datetime

###########################################
#            配置部分 - 修改这里            #
###########################################

# Utopixel API基础URL
UTOPIXEL_BASE_URL = "https://api.utopixel.art/api/user"

# 令牌交换端点
EXCHANGE_TOKEN_ENDPOINT = f"{UTOPIXEL_BASE_URL}/auth/exchange"

# 令牌将保存到此文件
TOKEN_FILE = "utopixel_tokens.json"

###########################################
#               脚本逻辑                  #
###########################################

print("===== Utopixel令牌获取工具 =====\n")

# 获取授权码
print("步骤1: 输入授权码...")
print("请输入您从浏览器回调URL中获取的授权码")
print("(授权码在回调URL的'code'参数中，例如: ?code=THIS_IS_THE_CODE)")
authorization_code = input("\n请输入授权码: ").strip()

if not authorization_code:
    print("\n错误: 未提供授权码，无法继续。")
    print("请运行 1_auth_url.py 获取登录URL，完成授权后再运行此脚本。")
    exit(1)

# 准备交换令牌的请求
print("\n步骤2: 准备令牌交换请求...")
print(f"* 令牌交换端点: {EXCHANGE_TOKEN_ENDPOINT}")
print(f"* 使用授权码: {authorization_code[:10]}... (部分显示)")

request_data = {
    "code": authorization_code
}

print("\n步骤3: 发送令牌交换请求...")
try:
    response = requests.post(
        EXCHANGE_TOKEN_ENDPOINT,
        json=request_data,
        headers={"Content-Type": "application/json"}
    )
    
    print(f"* 请求发送成功 (HTTP状态码: {response.status_code})")
    
    # 尝试解析响应
    if response.status_code == 200:
        token_data = response.json()
        print("* 响应解析成功")
    else:
        print(f"* 错误: 服务器返回状态码 {response.status_code}")
        print(f"* 响应内容: {response.text}")
        exit(1)
        
except Exception as e:
    print(f"* 错误: 请求失败 - {str(e)}")
    exit(1)

# 处理响应数据
print("\n步骤4: 处理令牌数据...")

# 检查响应状态
status = token_data.get('status', {})
status_code = status.get('code', -1)

if status_code != 0:
    print("* 错误: API返回错误状态")
    print(f"* 错误码: {status_code}")
    print(f"* 错误信息: {status.get('message', '未知错误')}")
    print(f"* 完整响应: {json.dumps(token_data, indent=2)}")
    exit(1)

if 'access_token' not in token_data:
    print("* 错误: 响应中没有访问令牌")
    print(f"* 完整响应: {json.dumps(token_data, indent=2)}")
    exit(1)

print("* 令牌获取成功!")

# 显示令牌信息
access_token = token_data.get('access_token', '')
token_type = token_data.get('token_type', '')
expires_in = token_data.get('expires_in', 0)
refresh_token = token_data.get('refresh_token', '')

print("\n===== 令牌信息 =====")
print(f"访问令牌: {access_token[:15]}... (已截断)")
print(f"令牌类型: {token_type}")
print(f"过期时间: {expires_in} 秒")
if refresh_token:
    print(f"刷新令牌: {refresh_token[:15]}... (已截断)")

# 显示用户信息
if 'user' in token_data:
    user = token_data['user']
    print("\n===== 用户信息 =====")
    print(f"用户ID: {user.get('id', '')}")
    print(f"用户名: {user.get('username', '')}")
    print(f"邮箱: {user.get('email', '')}")
    print(f"状态: {user.get('status', '')}")

# 添加令牌过期时间
current_time = time.time()
token_data['obtained_at'] = current_time
token_data['expires_at'] = current_time + expires_in

# 保存令牌数据到文件
print("\n步骤5: 保存令牌数据...")
try:
    with open(TOKEN_FILE, 'w', encoding='utf-8') as f:
        json.dump(token_data, f, indent=2, ensure_ascii=False)
    print(f"* 令牌数据已保存到: {TOKEN_FILE}")
    print(f"* 文件包含访问令牌和刷新令牌")
    print(f"* 令牌获取时间: {datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"* 令牌过期时间: {datetime.fromtimestamp(current_time + expires_in).strftime('%Y-%m-%d %H:%M:%S')}")
except Exception as e:
    print(f"* 警告: 无法保存令牌数据 - {str(e)}")

print("\n===== 下一步 =====")
print("运行 3_call_api.py 使用访问令牌调用API") 
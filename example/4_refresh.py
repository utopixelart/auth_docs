#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
刷新访问令牌的示例脚本
当访问令牌过期时，使用刷新令牌获取新的访问令牌
"""

import json
import requests
import os
import time
from datetime import datetime

###########################################
#            配置部分 - 修改这里            #
###########################################

# Utopixel API基础URL
UTOPIXEL_BASE_URL = "https://api.utopixel.art/api/user"

# 刷新令牌端点
REFRESH_TOKEN_ENDPOINT = f"{UTOPIXEL_BASE_URL}/auth/refresh"

# 令牌文件路径
TOKEN_FILE = "utopixel_tokens.json"

###########################################
#               脚本逻辑                  #
###########################################

print("===== Utopixel令牌刷新工具 =====\n")

# 步骤1: 读取令牌文件
print("步骤1: 读取保存的令牌...")
if not os.path.exists(TOKEN_FILE):
    print(f"* 错误: 令牌文件 {TOKEN_FILE} 不存在")
    print("* 请先运行 2_token.py 获取访问令牌和刷新令牌")
    exit(1)

try:
    with open(TOKEN_FILE, 'r', encoding='utf-8') as f:
        token_data = json.load(f)
    print("* 令牌文件读取成功")
except Exception as e:
    print(f"* 错误: 无法读取令牌文件 - {str(e)}")
    exit(1)

# 步骤2: 检查刷新令牌
print("\n步骤2: 检查刷新令牌...")
refresh_token = token_data.get('refresh_token')
if not refresh_token:
    print("* 错误: 令牌文件中没有刷新令牌")
    print("* 请重新运行认证流程获取新的令牌")
    exit(1)

# 检查访问令牌是否已过期
access_token = token_data.get('access_token')
expires_at = token_data.get('expires_at', 0)
current_time = time.time()

if current_time < expires_at:
    remaining_time = int(expires_at - current_time)
    print(f"* 注意: 当前访问令牌尚未过期，还剩 {remaining_time} 秒")
    print(f"* 过期时间: {datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 询问是否继续刷新
    continue_anyway = input("\n访问令牌尚未过期，是否仍然刷新? (y/n): ").strip().lower()
    if continue_anyway != 'y':
        print("已取消刷新。")
        exit(0)
    print("* 继续刷新令牌...")

# 步骤3: 准备刷新令牌请求
print("\n步骤3: 准备刷新令牌请求...")
print(f"* 刷新端点: {REFRESH_TOKEN_ENDPOINT}")
print(f"* 使用刷新令牌: {refresh_token[:15]}... (已截断)")

request_data = {
    "refresh_token": refresh_token
}

# 步骤4: 发送刷新令牌请求
print("\n步骤4: 发送刷新令牌请求...")
try:
    response = requests.post(
        REFRESH_TOKEN_ENDPOINT,
        json=request_data,
        headers={"Content-Type": "application/json"}
    )
    
    print(f"* 请求发送成功 (HTTP状态码: {response.status_code})")
    
    # 尝试解析响应
    if response.status_code == 200:
        new_token_data = response.json()
        print("* 响应解析成功")
    else:
        print(f"* 错误: 服务器返回状态码 {response.status_code}")
        print(f"* 响应内容: {response.text}")
        exit(1)
        
except Exception as e:
    print(f"* 错误: 请求失败 - {str(e)}")
    exit(1)

# 步骤5: 处理刷新令牌响应
print("\n步骤5: 处理刷新令牌响应...")

# 检查响应状态
status = new_token_data.get('status', {})
status_code = status.get('code', -1)

if status_code != 0:
    print("* 错误: API返回错误状态")
    print(f"* 错误码: {status_code}")
    print(f"* 错误信息: {status.get('message', '未知错误')}")
    print(f"* 完整响应: {json.dumps(new_token_data, indent=2)}")
    exit(1)

if 'access_token' not in new_token_data:
    print("* 错误: 响应中没有新的访问令牌")
    print(f"* 完整响应: {json.dumps(new_token_data, indent=2)}")
    exit(1)

print("* 令牌刷新成功!")

# 显示新令牌信息
new_access_token = new_token_data.get('access_token', '')
token_type = new_token_data.get('token_type', token_data.get('token_type', 'Bearer'))
expires_in = new_token_data.get('expires_in', 0)
new_refresh_token = new_token_data.get('refresh_token', '')  # 某些系统可能会轮换刷新令牌

print("\n===== 新令牌信息 =====")
print(f"新访问令牌: {new_access_token[:15]}... (已截断)")
print(f"令牌类型: {token_type}")
print(f"过期时间: {expires_in} 秒")

# 更新令牌数据
token_data['access_token'] = new_access_token
token_data['token_type'] = token_type
token_data['expires_in'] = expires_in
token_data['obtained_at'] = current_time
token_data['expires_at'] = current_time + expires_in

# 如果响应中包含新的刷新令牌，也要更新
if new_refresh_token:
    print(f"新刷新令牌: {new_refresh_token[:15]}... (已截断)")
    print("* 注意: 服务器返回了新的刷新令牌（令牌轮换）")
    token_data['refresh_token'] = new_refresh_token

# 步骤6: 保存更新后的令牌数据
print("\n步骤6: 保存更新后的令牌数据...")
try:
    with open(TOKEN_FILE, 'w', encoding='utf-8') as f:
        json.dump(token_data, f, indent=2, ensure_ascii=False)
    print(f"* 更新后的令牌数据已保存到: {TOKEN_FILE}")
    print(f"* 新令牌获取时间: {datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"* 新令牌过期时间: {datetime.fromtimestamp(current_time + expires_in).strftime('%Y-%m-%d %H:%M:%S')}")
except Exception as e:
    print(f"* 警告: 无法保存更新后的令牌数据 - {str(e)}")

print("\n===== 总结 =====")
print("1. 成功使用刷新令牌获取了新的访问令牌")
print("2. 新的访问令牌已保存到令牌文件")
print("3. 您现在可以使用新的访问令牌调用API")

print("\n===== 下一步 =====")
print("运行 3_call_api.py 使用新的访问令牌调用API") 
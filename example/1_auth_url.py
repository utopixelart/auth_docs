#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
生成Utopixel登录URL的示例脚本
用户需要手动复制此URL到浏览器中完成登录
"""

import urllib.parse

###########################################
#            配置部分 - 修改这里            #
###########################################

# Utopixel API基础URL
UTOPIXEL_BASE_URL = "https://api.utopixel.art/api/user"

# 您的租户ID，从Utopixel管理员处获取
UTOPIXEL_TENANT_ID = "your_tenant_id"  # 替换为您的实际租户ID

# 您注册的回调URL，Utopixel会在用户授权后重定向到此URL
REDIRECT_URI = "http://localhost:5000/auth/callback"  # 替换为您注册的回调URL

# 认证提供商，目前支持"google"
PROVIDER = "google"

###########################################
#               脚本逻辑                  #
###########################################

print("===== Utopixel认证URL生成工具 =====\n")

print("步骤1: 准备认证所需参数...")
print(f"* 使用租户ID: {UTOPIXEL_TENANT_ID}")
print(f"* 回调URL: {REDIRECT_URI}")
print(f"* 认证提供商: {PROVIDER}")

print("\n步骤2: 构建认证URL...")
auth_endpoint = f"{UTOPIXEL_BASE_URL}/auth/{PROVIDER}"

# 构建查询参数
params = {
    'tenant_id': UTOPIXEL_TENANT_ID,
    'redirect_url': REDIRECT_URI
}

# 构建并URL编码
encoded_params = urllib.parse.urlencode(params)
auth_url = f"{auth_endpoint}?{encoded_params}"

print("\n===== 认证URL已生成 =====")
print("\n" + auth_url + "\n")

print("===== 使用说明 =====")
print("1. 复制上面的完整URL")
print("2. 将URL粘贴到浏览器地址栏并访问")
print("3. 在Utopixel页面上完成登录授权")
print("4. 授权成功后，您将被重定向到您的回调URL")
print("5. 从回调URL中复制'code'参数的值")
print(f"   例如: {REDIRECT_URI}?code=AUTHORIZATION_CODE")
print("   您需要复制AUTHORIZATION_CODE部分")

print("\n===== 下一步 =====")
print("运行 2_token.py 并输入您获取到的授权码") 
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
生成Utopixel登录URL的示例脚本
用户需要访问此URL进行登录授权
"""

import urllib.parse
import webbrowser
import argparse

# 配置信息 - 使用前请修改这些值
UTOPIXEL_BASE_URL = "https://api.utopixel.art/api/user"
UTOPIXEL_TENANT_ID = "your_tenant_id"  # 替换为您的租户ID
REDIRECT_URI = "http://localhost:5000/auth/callback"  # 替换为您注册的回调URL
PROVIDER = "google"  # 目前支持的提供商

def generate_login_url():
    """生成Utopixel登录URL"""
    auth_endpoint = f"{UTOPIXEL_BASE_URL}/auth/{PROVIDER}"
    
    # 构建查询参数
    params = {
        'tenant_id': UTOPIXEL_TENANT_ID,
        'redirect_url': REDIRECT_URI
    }
    
    # 构建完整的认证URL
    auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
    return auth_url

def main():
    """脚本入口点"""
    parser = argparse.ArgumentParser(description='生成Utopixel登录URL')
    parser.add_argument('--open', action='store_true', help='自动在浏览器中打开URL')
    args = parser.parse_args()
    
    login_url = generate_login_url()
    
    print("\n=== Utopixel登录URL ===")
    print(login_url)
    print("\n使用说明:")
    print("1. 复制上面的URL到浏览器访问")
    print("2. 在Utopixel完成登录")
    print("3. 登录成功后，您将被重定向到您的回调URL")
    print("4. 从回调URL的查询参数中提取'code'参数，用于下一步获取访问令牌")
    print(f"   示例: {REDIRECT_URI}?code=AUTHORIZATION_CODE")
    print("\n下一步:")
    print("使用获取到的授权码运行 2_exchange_token.py")
    
    if args.open:
        print("\n正在自动打开浏览器...")
        webbrowser.open(login_url)

if __name__ == "__main__":
    main() 
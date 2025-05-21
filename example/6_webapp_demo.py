#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utopixel认证服务完整Web应用演示脚本
集成了完整的OAuth认证流程，包括:
- 登录跳转
- 授权码回调处理
- 令牌交换与刷新
- 使用令牌调用API
"""

import os
import json
import time
import urllib.parse
import hmac
import hashlib
import uuid
from datetime import datetime
from flask import Flask, request, redirect, session, render_template_string, jsonify, url_for
import requests

###########################################
#            配置部分 - 修改这里            #
###########################################

# Utopixel API基础URL
UTOPIXEL_BASE_URL = "https://api.utopixel.art/api/user"

# 认证端点
AUTH_ENDPOINT = f"{UTOPIXEL_BASE_URL}/auth/google"  # 使用Google登录
EXCHANGE_TOKEN_ENDPOINT = f"{UTOPIXEL_BASE_URL}/auth/exchange"
REFRESH_TOKEN_ENDPOINT = f"{UTOPIXEL_BASE_URL}/auth/refresh"
VERIFY_TOKEN_ENDPOINT = f"{UTOPIXEL_BASE_URL}/auth/verify_token"

# 您的Utopixel应用信息，从Utopixel管理员处获取
TENANT_ID = "your_tenant_id"  # 替换为您的租户ID
APP_KEY = "your_app_key"      # 替换为您的App Key
SECRET_KEY = "your_secret_key"  # 替换为您的Secret Key

# Flask应用配置
APP_HOST = "localhost"
APP_PORT = 5000
APP_SECRET_KEY = "demo_secret_key_change_in_production"  # Flask session密钥
REDIRECT_URI = f"http://{APP_HOST}:{APP_PORT}/auth/callback"

###########################################
#               Flask应用                 #
###########################################

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'

# HTML模板 - 为了简化示例，我们使用内联模板
INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Utopixel认证演示</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .container { border: 1px solid #ddd; padding: 20px; border-radius: 5px; }
        .btn { padding: 10px 15px; background: #4CAF50; color: white; border: none; border-radius: 3px; cursor: pointer; }
        .btn-secondary { background: #2196F3; }
        .btn-danger { background: #f44336; }
        .code { background: #f5f5f5; padding: 10px; border: 1px solid #ddd; overflow: auto; }
        .success { color: green; }
        .error { color: red; }
        .hidden { display: none; }
    </style>
</head>
<body>
    <h1>Utopixel认证服务演示</h1>
    
    <div class="container">
        <h2>认证状态</h2>
        {% if is_authenticated %}
            <p class="success">✓ 已认证</p>
            <p>用户ID: {{ user_info.id }}</p>
            <p>用户名: {{ user_info.username }}</p>
            <p>邮箱: {{ user_info.email }}</p>
            <p>状态: {{ user_info.status }}</p>
            <p>令牌过期时间: {{ token_expires_at }}</p>
            <hr>
            <button id="logout" class="btn btn-danger">注销</button>
            <button id="call-api" class="btn btn-secondary">调用API</button>
            <button id="refresh-token" class="btn btn-secondary">刷新令牌</button>
        {% else %}
            <p class="error">✗ 未认证</p>
            <a href="/login" class="btn">使用Utopixel账号登录</a>
        {% endif %}
    </div>
    
    {% if is_authenticated %}
    <div id="api-result" class="container hidden">
        <h2>API调用结果</h2>
        <pre id="api-response" class="code"></pre>
    </div>
    {% endif %}
    
    <div class="container">
        <h2>流程说明</h2>
        <ol>
            <li>点击登录按钮 - 重定向到Utopixel认证服务</li>
            <li>在Utopixel页面完成登录</li>
            <li>登录成功后，Utopixel将您重定向回应用并附带授权码</li>
            <li>应用使用授权码交换访问令牌和刷新令牌</li>
            <li>应用使用访问令牌调用API</li>
            <li>访问令牌过期时，应用可使用刷新令牌获取新的访问令牌</li>
        </ol>
    </div>
    
    <script>
        {% if is_authenticated %}
        document.getElementById('call-api').addEventListener('click', async function() {
            document.getElementById('api-result').classList.remove('hidden');
            document.getElementById('api-response').textContent = '正在调用API...';
            
            try {
                const response = await fetch('/api/user-info');
                const data = await response.json();
                document.getElementById('api-response').textContent = JSON.stringify(data, null, 2);
            } catch (error) {
                document.getElementById('api-response').textContent = '调用API失败: ' + error.message;
            }
        });
        
        document.getElementById('refresh-token').addEventListener('click', async function() {
            document.getElementById('api-result').classList.remove('hidden');
            document.getElementById('api-response').textContent = '正在刷新令牌...';
            
            try {
                const response = await fetch('/auth/refresh', { method: 'POST' });
                const data = await response.json();
                document.getElementById('api-response').textContent = JSON.stringify(data, null, 2);
                if (data.success) {
                    // 刷新页面以更新令牌信息
                    setTimeout(() => location.reload(), 2000);
                }
            } catch (error) {
                document.getElementById('api-response').textContent = '刷新令牌失败: ' + error.message;
            }
        });
        
        document.getElementById('logout').addEventListener('click', function() {
            window.location.href = '/logout';
        });
        {% endif %}
    </script>
</body>
</html>
"""

###########################################
#               辅助函数                  #
###########################################

def is_token_expired():
    """检查令牌是否过期"""
    if 'expires_at' not in session:
        return True
    
    return time.time() >= session['expires_at']

def generate_hmac_sha256(data, key):
    """生成HMAC-SHA256签名"""
    h = hmac.new(key.encode(), data.encode(), hashlib.sha256)
    return h.hexdigest()

def api_request(method, endpoint, data=None, use_app_key=False):
    """
    发送API请求
    如果use_app_key为True，使用App Key和Secret Key签名请求
    否则使用访问令牌
    """
    headers = {"Content-Type": "application/json"}
    request_data = data or {}
    
    if use_app_key:
        # 使用App Key和Secret Key签名请求
        timestamp = str(int(time.time()))
        
        # 将认证信息添加到请求体中
        request_data.update({
            "app_key": APP_KEY,
            "timestamp": timestamp
        })
        
        # 生成签名
        token = request_data.get("token", "")
        signature_string = f"{timestamp}+{token}"
        signature = generate_hmac_sha256(signature_string, SECRET_KEY)
        
        # 将签名添加到请求体
        request_data["signature"] = signature
    else:
        # 使用访问令牌
        if 'access_token' not in session:
            raise Exception("没有访问令牌")
            
        headers["Authorization"] = f"Bearer {session['access_token']}"
    
    if method == "GET":
        response = requests.get(endpoint, headers=headers)
    else:  # POST
        response = requests.post(endpoint, headers=headers, json=request_data)
        
    return response

###########################################
#               路由处理                  #
###########################################

@app.route('/')
def index():
    """主页，展示认证状态和操作按钮"""
    is_authenticated = 'access_token' in session
    user_info = session.get('user_info', {})
    token_expires_at = datetime.fromtimestamp(session.get('expires_at', 0)).strftime('%Y-%m-%d %H:%M:%S') if is_authenticated else ''
    
    return render_template_string(
        INDEX_TEMPLATE, 
        is_authenticated=is_authenticated,
        user_info=user_info,
        token_expires_at=token_expires_at
    )

@app.route('/login')
def login():
    """重定向用户到Utopixel登录页面"""
    params = {
        'tenant_id': TENANT_ID,
        'redirect_url': REDIRECT_URI
    }
    
    auth_url = f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    print(f"重定向到登录URL: {auth_url}")
    
    return redirect(auth_url)

@app.route('/auth/callback')
def auth_callback():
    """处理授权回调，获取访问令牌"""
    code = request.args.get('code')
    if not code:
        error = request.args.get('error', '未知错误')
        error_description = request.args.get('error_description', '')
        return f"授权失败: {error} - {error_description}", 400
    
    print(f"收到授权码: {code[:10]}...")
    
    # 使用授权码交换令牌
    try:
        response = requests.post(
            EXCHANGE_TOKEN_ENDPOINT,
            json={"code": code},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code != 200:
            return f"令牌交换失败 ({response.status_code}): {response.text}", 400
            
        token_data = response.json()
        
        # 检查响应状态
        status = token_data.get('status', {})
        if status.get('code', -1) != 0:
            return f"令牌交换失败: {status.get('message', '未知错误')}", 400
        
        # 保存令牌数据到会话
        session['access_token'] = token_data['access_token']
        session['token_type'] = token_data.get('token_type', 'Bearer')
        session['refresh_token'] = token_data.get('refresh_token', '')
        
        # 保存令牌过期时间
        expires_in = token_data.get('expires_in', 3600)
        session['expires_at'] = time.time() + expires_in
        
        # 保存用户信息
        if 'user' in token_data:
            session['user_info'] = token_data['user']
            
        print(f"令牌交换成功，用户: {session['user_info'].get('username', '')}")
        
        return redirect('/')
        
    except Exception as e:
        return f"令牌交换过程中发生错误: {str(e)}", 500

@app.route('/auth/refresh', methods=['POST'])
def refresh_token():
    """刷新访问令牌"""
    if 'refresh_token' not in session:
        return jsonify({"success": False, "error": "没有刷新令牌"}), 400
        
    try:
        response = requests.post(
            REFRESH_TOKEN_ENDPOINT,
            json={"refresh_token": session['refresh_token']},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code != 200:
            return jsonify({
                "success": False, 
                "error": f"刷新令牌失败 ({response.status_code})", 
                "details": response.text
            }), 400
            
        token_data = response.json()
        
        # 检查响应状态
        status = token_data.get('status', {})
        if status.get('code', -1) != 0:
            return jsonify({
                "success": False,
                "error": f"刷新令牌失败: {status.get('message', '未知错误')}"
            }), 400
        
        # 更新会话中的令牌数据
        session['access_token'] = token_data['access_token']
        session['token_type'] = token_data.get('token_type', session['token_type'])
        
        # 如果响应中包含新的刷新令牌，也要更新
        if 'refresh_token' in token_data:
            session['refresh_token'] = token_data['refresh_token']
        
        # 更新令牌过期时间
        expires_in = token_data.get('expires_in', 3600)
        session['expires_at'] = time.time() + expires_in
        
        return jsonify({
            "success": True,
            "message": "令牌刷新成功",
            "expires_at": datetime.fromtimestamp(session['expires_at']).strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": f"刷新令牌过程中发生错误: {str(e)}"}), 500

@app.route('/api/user-info')
def get_user_info():
    """使用访问令牌调用API获取用户信息"""
    if 'access_token' not in session:
        return jsonify({"success": False, "error": "未认证", "status": {"code": 1, "message": "未认证"}}), 401
        
    if is_token_expired():
        return jsonify({
            "success": False, 
            "error": "访问令牌已过期", 
            "message": "请点击'刷新令牌'按钮",
            "status": {"code": 1, "message": "访问令牌已过期"}
        }), 401
    
    # 模拟API调用，返回会话中保存的用户信息
    # 在实际应用中，您应该使用访问令牌调用实际的API
    user_info = session.get('user_info', {})
    
    return jsonify({
        "success": True,
        "data": {
            "user": user_info,
            "token_info": {
                "expires_at": datetime.fromtimestamp(session['expires_at']).strftime('%Y-%m-%d %H:%M:%S'),
                "is_expired": is_token_expired()
            }
        },
        "status": {
            "code": 0,
            "message": "Success"
        }
    })

@app.route('/logout')
def logout():
    """用户注销，清除会话数据"""
    session.clear()
    return redirect('/')

###########################################
#               启动应用                  #
###########################################

if __name__ == '__main__':
    print(f"\n===== Utopixel认证服务Web演示 =====")
    print(f"* 启动服务器: http://{APP_HOST}:{APP_PORT}")
    print(f"* 认证回调URL: {REDIRECT_URI}")
    print(f"* 租户ID: {TENANT_ID}")
    print("\n提示: 在浏览器中访问上面的URL开始演示")
    print("===================================\n")
    
    app.run(host=APP_HOST, port=APP_PORT, debug=True) 
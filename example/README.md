# Utopixel 认证服务Python脚本示例

这个目录包含了一系列独立的Python脚本，每个脚本演示Utopixel认证服务的不同部分。每个脚本都是完全独立的，不依赖其他文件，可以直接单独运行。

## 脚本列表

1. `1_auth_url.py` - 生成Utopixel登录URL
2. `2_token.py` - 使用授权码交换访问令牌和刷新令牌
3. `3_call_api.py` - 使用访问令牌发起API请求
4. `4_refresh.py` - 使用刷新令牌获取新的访问令牌
5. `5_backend_verify_token.py` - 后端验证访问令牌的有效性
6. `6_webapp_demo.py` - 简单的Web应用，展示完整的认证流程

## 使用方法

1. 首先安装必要的依赖：
   ```
   pip install requests flask
   ```

2. 每个脚本都包含自己的配置部分，运行前请直接修改脚本顶部的配置变量：
   - `UTOPIXEL_BASE_URL` - API基础URL (默认: https://api.utopixel.art/api/user)
   - `UTOPIXEL_TENANT_ID` - 租户ID
   - `UTOPIXEL_APP_KEY` - 应用Key 
   - `UTOPIXEL_SECRET_KEY` - 应用Secret Key
   - `REDIRECT_URI` - 您的回调URL

3. 按照编号顺序运行脚本，了解完整的认证流程：
   ```
   python 1_auth_url.py  # 生成登录URL
   # 手动打开URL并完成登录，获取授权码
   python 2_token.py  # 使用授权码获取令牌
   python 3_call_api.py  # 使用获取的令牌调用API
   ```

4. 要启动完整的Web演示，运行：
   ```
   python 6_webapp_demo.py
   ```
   然后在浏览器中访问 http://localhost:5000

## 认证流程说明

1. **生成登录URL** (脚本1): 构建Utopixel认证URL，用户需要访问此URL进行登录
2. **获取授权码**: 用户登录后，Utopixel将用户重定向到您的回调URL，并附带授权码
3. **交换令牌** (脚本2): 使用授权码交换访问令牌和刷新令牌
4. **使用访问令牌** (脚本3): 通过在请求头中包含访问令牌，访问受保护的API
5. **刷新令牌** (脚本4): 当访问令牌过期时，使用刷新令牌获取新的访问令牌
6. **后端验证** (脚本5): 展示后端如何验证从前端接收到的访问令牌
6. **完整演示** (脚本6): Web应用演示，集成了完整的认证流程

## 注意事项

- 这些脚本是为了演示目的而创建的，实际生产环境需要更完善的错误处理和安全措施
- 脚本中暂时使用简单的文件方式存储令牌，生产环境应使用更安全的存储方式
- 运行脚本前确保您已经在Utopixel平台注册了应用并获取了必要的凭证 
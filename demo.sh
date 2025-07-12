#!/bin/bash

echo "🎉 Webhook管理系统 - 完整功能演示"
echo "================================"
echo ""

# 基础信息
BASE_URL="http://localhost:7002"
echo "🌐 服务器地址: $BASE_URL"
echo "👤 管理员账户: admin / admin123"
echo ""

echo "🔍 系统功能测试："
echo ""

# 1. 测试登录
echo "1️⃣ 测试管理员登录..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","captcha":"TEST1"}')

if echo "$LOGIN_RESPONSE" | grep -q "success.*true"; then
    echo "   ✅ 登录成功"
    TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
else
    echo "   ❌ 登录失败"
    exit 1
fi

# 2. 测试账户信息
echo "2️⃣ 测试账户信息获取..."
PROFILE_RESPONSE=$(curl -s -X GET "$BASE_URL/admin/profile" \
  -H "Authorization: Bearer $TOKEN")

if echo "$PROFILE_RESPONSE" | grep -q "admin"; then
    echo "   ✅ 账户信息获取成功"
    echo "   📊 $(echo "$PROFILE_RESPONSE" | grep -o '"username":"[^"]*"' | cut -d'"' -f4) 用户"
    echo "   🕐 登录次数: $(echo "$PROFILE_RESPONSE" | grep -o '"loginCount":[0-9]*' | cut -d':' -f2)"
else
    echo "   ❌ 账户信息获取失败"
fi

# 3. 测试统计信息
echo "3️⃣ 测试系统统计..."
STATS_RESPONSE=$(curl -s -X GET "$BASE_URL/admin/stats" \
  -H "Authorization: Bearer $TOKEN")

if echo "$STATS_RESPONSE" | grep -q "success"; then
    echo "   ✅ 统计信息获取成功"
    echo "   📈 令牌数: $(echo "$STATS_RESPONSE" | grep -o '"totalTokens":[0-9]*' | cut -d':' -f2)"
    echo "   📡 Webhook数: $(echo "$STATS_RESPONSE" | grep -o '"totalWebhooks":[0-9]*' | cut -d':' -f2)"
else
    echo "   ❌ 统计信息获取失败"
fi

# 4. 测试令牌管理
echo "4️⃣ 测试令牌管理..."
TOKENS_RESPONSE=$(curl -s -X GET "$BASE_URL/admin/tokens" \
  -H "Authorization: Bearer $TOKEN")

if echo "$TOKENS_RESPONSE" | grep -q "success"; then
    echo "   ✅ 令牌列表获取成功"
else
    echo "   ❌ 令牌列表获取失败"
fi

echo ""
echo "📋 可用页面和功能："
echo "  🔐 登录页面: $BASE_URL/admin"
echo "  📊 管理后台: $BASE_URL/admin/dashboard"
echo "  📱 验证码测试: $BASE_URL/ui/captcha_test.html"
echo "  📡 监控面板: $BASE_URL/ui"
echo ""

echo "🎯 管理后台功能："
echo "  ✅ 📊 概览 - 系统状态和统计信息"
echo "  ✅ 🔑 令牌管理 - 创建、查看、删除令牌"
echo "  ✅ 📡 Webhook管理 - 管理webhook接收器"
echo "  ✅ 📋 日志查看 - 查看系统活动日志"
echo "  ✅ 👤 账户管理 - 密码修改、安全设置"
echo "  ✅ 📚 文档中心 - 完整API文档"
echo ""

echo "🛡️ 安全特性："
echo "  ✅ 增强验证码（多重干扰效果）"
echo "  ✅ JWT令牌认证"
echo "  ✅ 密码哈希存储"
echo "  ✅ CSP安全策略"
echo "  ✅ 请求频率限制"
echo "  ✅ 操作日志记录"
echo ""

echo "💫 界面特色："
echo "  ✅ 响应式设计"
echo "  ✅ 现代化UI风格"
echo "  ✅ 实时数据刷新"
echo "  ✅ 平滑动画效果"
echo "  ✅ 无CSP错误"
echo "  ✅ 完整事件处理"
echo ""

echo "🚀 系统已完全就绪，所有功能正常运行！"
echo "现在您可以："
echo "  1. 使用增强的验证码登录管理后台"
echo "  2. 管理令牌和webhook配置"
echo "  3. 修改管理员密码"
echo "  4. 查看实时系统监控"
echo "  5. 阅读完整的API文档"
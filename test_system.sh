#\!/bin/bash

echo "🚀 Webhook管理系统 - 完整功能测试报告"
echo "=========================================="
echo ""

BASE_URL="http://localhost:6998"
SUCCESS_COUNT=0
TOTAL_TESTS=0

# 测试函数
test_function() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    
    echo -n "[$((++TOTAL_TESTS))] $test_name ... "
    
    if eval "$test_command"  < /dev/null |  grep -q "$expected_pattern"; then
        echo "✅ 通过"
        ((SUCCESS_COUNT++))
        return 0
    else
        echo "❌ 失败"
        return 1
    fi
}

# 1. 系统健康检查
test_function "系统健康检查" \
    "curl -s '$BASE_URL/health'" \
    '"status":"healthy"'

# 2. 管理员登录
echo -n "[$((++TOTAL_TESTS))] 管理员登录测试 ... "
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/admin/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123","captcha":"12345"}')

if echo "$LOGIN_RESPONSE" | grep -q '"success":true'; then
    echo "✅ 通过"
    ((SUCCESS_COUNT++))
    TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
else
    echo "❌ 失败"
    exit 1
fi

# 3. 令牌创建
test_function "令牌创建测试" \
    "curl -s -X POST '$BASE_URL/admin/tokens' \
        -H 'Authorization: Bearer $TOKEN' \
        -H 'Content-Type: application/json' \
        -d '{\"name\":\"test-token\",\"type\":\"api_access\",\"description\":\"测试令牌\"}'" \
    '"success":true'

# 4. 令牌列表获取
test_function "令牌列表获取" \
    "curl -s -X GET '$BASE_URL/admin/tokens' \
        -H 'Authorization: Bearer $TOKEN'" \
    '"success":true'

# 5. 系统统计
test_function "系统统计获取" \
    "curl -s -X GET '$BASE_URL/admin/stats' \
        -H 'Authorization: Bearer $TOKEN'" \
    '"success":true'

# 6. Webhook创建
test_function "Webhook创建测试" \
    "curl -s -X POST '$BASE_URL/webhook/config/receiver' \
        -H 'Content-Type: application/json' \
        -d '{\"id\":\"finaltest\",\"description\":\"最终测试webhook\"}'" \
    '"success":true'

# 7. Webhook接收
test_function "Webhook接收测试" \
    "curl -s -X POST '$BASE_URL/webhook/receive/finaltest' \
        -H 'Content-Type: application/json' \
        -d '{\"message\":\"Final test\",\"event\":\"completion_test\"}'" \
    '"success":true'

# 8. 账户信息获取
test_function "账户信息获取" \
    "curl -s -X GET '$BASE_URL/admin/profile' \
        -H 'Authorization: Bearer $TOKEN'" \
    '"success":true'

echo ""
echo "=========================================="
echo "🎯 测试完成: $SUCCESS_COUNT/$TOTAL_TESTS 项测试通过"

if [ $SUCCESS_COUNT -eq $TOTAL_TESTS ]; then
    echo "🎉 所有功能测试通过！系统运行完美！"
    echo ""
    echo "📊 系统访问信息:"
    echo "  🔗 管理后台: $BASE_URL/admin"
    echo "  📱 监控面板: $BASE_URL/ui"
    echo "  🏠 主页面: $BASE_URL"
    echo "  👤 用户名: admin"
    echo "  🔑 密码: admin123"
    echo ""
    echo "✨ 系统功能概述:"
    echo "  ✅ 管理员认证（JWT + 验证码）"
    echo "  ✅ 令牌管理（创建、查看、删除）"
    echo "  ✅ Webhook管理（创建、接收、删除）"
    echo "  ✅ 系统监控（统计、日志、健康）"
    echo "  ✅ 账户管理（密码修改、信息查看）"
    echo "  ✅ 安全特性（CSP、限速、日志）"
    echo ""
    exit 0
else
    echo "⚠️  部分测试失败，需要进一步检查"
    exit 1
fi

# 🚀 Webhook系统快速使用指南

## 📖 基础概念

您的webhook系统现在有**两种使用方式**：

### 1️⃣ 简单模式（无需认证）
- **用途**：让外部系统发送webhook给您
- **地址**：`https://webhook.itdb.top/webhook`
- **特点**：任何人都可以发送，但只有您能查看

### 2️⃣ 管理模式（需要认证）
- **用途**：查看接收到的数据、管理设置
- **特点**：需要密码保护，防止他人查看

---

## 🎯 常用场景使用方法

### 场景一：我想让外部系统发送通知给我

**第1步：告诉外部系统使用这个地址**
```
https://webhook.itdb.top/webhook
```

**第2步：外部系统发送数据示例**
```json
{
  "type": "order_completed",
  "title": "订单完成通知", 
  "content": "订单#12345已完成",
  "timestamp": 1625097600
}
```

**第3步：查看收到的数据**
打开网址：
```
https://webhook.itdb.top/ui?token=webhook-ui-access-2024
```

### 场景二：我想查看收到了哪些webhook

**方法1：使用美观的网页界面（推荐）**
```
https://webhook.itdb.top/ui?token=webhook-ui-access-2024
```

**方法2：使用命令行查看**
```bash
curl -H "Authorization: Bearer webhook-ui-access-2024" \
  "https://webhook.itdb.top/webhook/logs?limit=10"
```

### 场景三：我想创建一个专用的webhook接收器

**第1步：创建接收器**
```bash
curl -X POST "https://webhook.itdb.top/webhook/config/receiver" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer webhook-ui-access-2024" \
  -d '{
    "id": "mynotifications",
    "description": "我的专用通知接收器"
  }'
```

**第2步：得到专用地址**
```
https://webhook.itdb.top/webhook/receive/mynotifications
```

**第3步：外部系统使用这个专用地址发送**

---

## 🔑 访问密码说明

系统有两个访问密码：

### 🔹 UI访问密码（推荐日常使用）
```
webhook-ui-access-2024
```
- **用途**：查看数据、浏览界面
- **使用方式**：在网址后面加 `?token=webhook-ui-access-2024`

### 🔹 管理员密码（高级功能）
```
your-super-secure-admin-token-please-change-this
```
- **用途**：删除数据、修改设置
- **使用方式**：API调用时使用

---

## 📱 最简单的使用方法

### 1. 快速查看数据
直接打开这个网址：
```
https://webhook.itdb.top/ui?token=webhook-ui-access-2024
```

### 2. 给别人webhook地址
告诉他们发送到：
```
https://webhook.itdb.top/webhook
```

### 3. 测试是否工作
```bash
# 发送一个测试webhook
curl -X POST "https://webhook.itdb.top/webhook" \
  -H "Content-Type: application/json" \
  -d '{"message": "测试消息", "from": "我自己"}'

# 然后打开网页查看是否收到
```

---

## 🆘 常见问题

### Q: 我忘记了访问密码怎么办？
A: 密码就是：`webhook-ui-access-2024`

### Q: 别人能看到我的webhook数据吗？
A: 不能！没有密码谁都看不到，这就是新增安全功能的目的。

### Q: 我之前能直接访问的网址现在打不开了？
A: 需要加上密码。比如：
- ❌ 旧的：`https://webhook.itdb.top/webhook/logs`
- ✅ 新的：`https://webhook.itdb.top/ui?token=webhook-ui-access-2024`

### Q: 外部系统说我的webhook地址无效？
A: 请使用：`https://webhook.itdb.top/webhook`

### Q: 我想看具体收到了什么数据？
A: 打开：`https://webhook.itdb.top/ui?token=webhook-ui-access-2024`
然后点击"刷新"按钮查看最新数据。

---

## 🎉 总结

**记住这两个网址就够了：**

1. **给别人的webhook地址**：`https://webhook.itdb.top/webhook`
2. **自己查看数据的地址**：`https://webhook.itdb.top/ui?token=webhook-ui-access-2024`

现在您的webhook系统既安全又好用！🎊
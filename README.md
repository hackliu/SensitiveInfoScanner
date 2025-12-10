# SensitiveInfoScanner

SensitiveInfoScanner 是一款用于扫描文本、文件、源代码等内容中的敏感信息的 Python 工具。工具支持自动识别密钥、凭证、令牌、密码、证书、访问密钥、加密材料等多类敏感数据，并将扫描结果分类记录到结构化日志文件中。
 本工具适用于安全审计、自查、合规检查、本地凭证治理等场景。

------

## 功能特性

- **多类型敏感信息识别**
  - API Key（多云厂商格式）
  - Access Token、Bearer Token、Session Token
  - 密码（Password）
  - 用户名可能泄漏信息（Username）
  - RSA/DSA/ECDSA 私钥、公钥
  - JWT Token
  - AES/RSA 等加密密钥片段
  - 数据库连接串（MySQL/PostgreSQL/Redis/MongoDB 等）
  - SSH 密钥、证书
  - 邮箱（Email Address）
  - 手机号与基础身份信息片段
  - 常见 Webhook
  - 代码环境变量泄漏（如 `SECRET_KEY=`、`TOKEN=`）
- **可扩展正则模板**
  - 所有敏感信息的检测基于可配置的正则表达式，可供用户按需扩展。
- **分类日志输出**
  - 日志按敏感信息类别进行结构化保存。
  - 自动记录时间、来源路径、命中的敏感项等。
- **支持扫描多种输入源**
  - 单个文件
  - 文件夹（递归扫描）
  - 直接输入的文本内容
- **可配置参数**
  - 扫描路径
  - 日志保存路径
  - 启用/禁用特定类别扫描
- **中文交互 CLI**
  - 提供清晰的命令行输入指引（中文界面）
  - 附加详细运行日志

------

## 使用方法

### 方式一：扫描文件或目录

```
python scanner.py --path ./your_project
```

### 方式二：扫描指定文件

```
python scanner.py --path secret.txt
```

### 方式三：扫描输入的文本字符串

```
python scanner.py --text "my password=123456"
```

### 方式四：自定义日志路径

```
python scanner.py --path ./src --log logs/output.log
```

------

## 日志输出结构

日志文件按如下结构存储示例：

```
[2025-01-01 13:40:21] CATEGORY: API_KEY
File: /project/config.js
Matched: AKIAIOSFODNN7EXAMPLE

[2025-01-01 13:40:21] CATEGORY: PASSWORD
File: /project/app.py
Matched: password = "123456"
```

------

## 支持的敏感信息类型（持续更新）

| 类别          | 描述                                           |
| ------------- | ---------------------------------------------- |
| API_KEY       | 各类服务 API Keys（AWS/GCP/Azure/Telegram 等） |
| ACCESS_TOKEN  | OAuth Token、Bearer Token、Session Token       |
| PASSWORD      | 常用密码字段                                   |
| USERNAME      | 用户名暴露                                     |
| ENCRYPT_KEY   | AES/RSA-key 片段                               |
| SSH_KEY       | id_rsa / PRIVATE KEY 内容                      |
| JWT           | JSON Web Token                                 |
| DB_CONNECTION | MySQL/PostgreSQL/Redis/MongoDB 等连接串        |
| EMAIL         | 邮箱地址                                       |
| WEBHOOK       | 钩子地址，如 Slack、Telegram、Jenkins          |
| CERTIFICATE   | 证书内容（BEGIN CERTIFICATE）                  |

------

## 扩展与自定义敏感规则

敏感规则储存在 `rules.py` 中，可直接添加：

```
CUSTOM_RULES = {
    "NEW_TYPE": r"your-regex-here"
}
```

添加后，系统会自动识别并记录相关匹配项。

------

## 示例输出

执行：

```
python scanner.py --path ./demo
```

输出：

```
扫描开始...
发现敏感信息: 7 项
日志已保存至 logs/sensitive.log
扫描完成
```



## 注意事项

- 本工具仅用于安全审计与风险排查，请勿用于非法用途。
- 扫描脚本不会上传任何数据，所有分析在本地完成。
- 建议在版本库提交前对项目运行扫描，避免敏感信息泄漏到 Git 平台。

------

## 许可证

本项目依据 MIT 协议发布，可自由使用、修改及分发。

------

## 更新计划

- 增加 AI 模型辅助识别模糊敏感内容
- 增加 Git commit 历史扫描功能
- 增加规则热加载机制

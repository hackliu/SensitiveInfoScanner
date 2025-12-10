import re
import os
import time

# --------------------------
# 日志目录初始化
# --------------------------
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# --------------------------
# 全量敏感信息规则（专业级）
# --------------------------
PATTERNS = {
    # -------------------- 基础网络信息 --------------------
    "IP": [
        re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
    ],
    "PortIP": [
        re.compile(r"\b\d{1,3}(\.\d{1,3}){3}:\d{2,5}\b")
    ],
    "Domain": [
        re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    ],
    "URL": [
        re.compile(r"https?://[^\s\"']+"),
        re.compile(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/[^\s\"']*")
    ],
    "WebSocket": [
        re.compile(r"wss?://[^\s\"']+")
    ],

    # -------------------- 加密算法与参数 --------------------
    "Algorithm": [
        re.compile(r"\bAES[- ]?(128|192|256)?\b", re.I),
        re.compile(r"\bRSA[- ]?\d{3,4}\b", re.I),
        re.compile(r"\bChaCha20\b", re.I),
        re.compile(r"\bSM2|SM3|SM4\b", re.I),
        re.compile(r"\bMD5|SHA[- ]?(1|256|384|512)\b", re.I)
    ],
    "CryptoParam": [
        re.compile(r"\b(iv|nonce|salt)[:=][A-Za-z0-9+/=]{8,}\b", re.I)
    ],

    # -------------------- 密钥、Token --------------------
    "Key": [
        re.compile(r"-----BEGIN PRIVATE KEY-----"),
        re.compile(r"\b[A-Fa-f0-9]{32,64}\b"),               # HEX key
        re.compile(r"\b[0-9A-Za-z+/]{20,}={0,2}\b")          # Base64 key
    ],
    "APIKey": [
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),           # Firebase
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                 # AWS
        re.compile(r"\bLTAI[0-9A-Za-z]{20,}\b"),             # Aliyun
        re.compile(r"\bAKID[0-9A-Za-z]{20,}\b"),             # Tencent Cloud
        re.compile(r"ghp_[0-9A-Za-z]{36}"),                  # GitHub Token
        re.compile(r"\bxox[bp]-[0-9A-Za-z-]+\b"),            # Slack Token
        re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{30,}\b"),    # Telegram Bot Token
    ],
    "Token": [
        re.compile(r"Bearer [A-Za-z0-9\-_.]+"),
        re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")  # JWT
    ],

    # -------------------- 账号 + 密码信息 --------------------
    "Account": [
        re.compile(r"\b(user(name)?|account)[:=][^\s\"']{1,40}", re.I),
        re.compile(r"\b(pass(word)?)[:=][^\s\"']{1,40}", re.I),
    ],
    "BasicAuth": [
        re.compile(r"Basic [A-Za-z0-9+/=]{8,}")
    ],

    # -------------------- 邮箱与手机号 --------------------
    "Email": [
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    ],
    "Phone": [
        re.compile(r"\b1[3-9]\d{9}\b")
    ],

    # -------------------- 云服务存储 --------------------
    "Cloud": [
        re.compile(r"s3\.amazonaws\.com/[^\s\"']+"),
        re.compile(r"oss-[a-z0-9-]+\.aliyuncs\.com"),
        re.compile(r"cos\.ap\-[a-z0-9-]+\.myqcloud\.com"),
    ],

    # -------------------- 数据库连接串 --------------------
    "DBConnection": [
        re.compile(r"mongodb://[^\s\"']+"),
        re.compile(r"redis://[^\s\"']+"),
        re.compile(r"mysql://[^\s\"']+"),
        re.compile(r"amqp://[^\s\"']+"),
        re.compile(r"mqtt://[^\s\"']+"),
    ],

    # -------------------- 调试信息泄露 --------------------
    "DebugString": [
        re.compile(r"/data/data/[A-Za-z0-9._-]+/"),
        re.compile(r"\bdebug[:=][^\s]{1,20}\b", re.I),
        re.compile(r"\b(staging|dev|test)\b", re.I)
    ]
}

# --------------------------
# 搜索结果容器
# --------------------------
RESULTS = {k: [] for k in PATTERNS.keys()}


# ------------------------------------------------------------
# 工具函数
# ------------------------------------------------------------
def find_files(root='.'):
    """递归扫描所有文件路径"""
    for base, _, files in os.walk(root):
        for f in files:
            yield os.path.join(base, f)


def extract_strings(data):
    """提取二进制中的可读 ASCII 字符串（4+ 长度）"""
    return re.findall(b'[ -~]{4,}', data)


def analyze_text(text):
    """匹配每条可读字符串，并归类到对应分类"""
    for category, regs in PATTERNS.items():
        for reg in regs:
            if reg.search(text):
                RESULTS[category].append(text)


def save_logs():
    """将所有扫描结果分类写入 logs 目录"""
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    for category, items in RESULTS.items():
        if not items:
            continue

        # 去重
        items = list(set(items))

        path = os.path.join(LOG_DIR, f"{category}_{timestamp}.log")
        with open(path, 'w', encoding='utf-8') as f:
            for item in items:
                f.write(item + "\n")

    print("\n扫描日志已保存到 logs/ 目录下。")


# ------------------------------------------------------------
# 主流程
# ------------------------------------------------------------
def main():
    print("敏感信息扫描器 V3.0 启动\n")

    for file in find_files('.'):
        print(f"扫描文件: {file}")

        try:
            with open(file, 'rb') as f:
                data = f.read()

            strings = extract_strings(data)

            for raw in strings:
                text = raw.decode('ascii', errors='ignore')
                analyze_text(text)

        except Exception as e:
            print(f"读取失败: {file} ({e})")

    save_logs()
    print("\n扫描完成。\n")


if __name__ == '__main__':
    main()

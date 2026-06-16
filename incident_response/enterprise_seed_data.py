"""企业知识库默认种子数据：8 条安全策略（中文）。"""

SEED_POLICIES = [
    {
        "title": "SQL 注入防护",
        "content": (
            "SQL 注入发生在不可信数据作为命令或查询的一部分发送到解释器时。"
            "攻击者可以通过参数、请求体或头部中未经过滤的输入执行任意 SQL。"
            "常见模式包括：' OR 1=1--、UNION SELECT 以及基于时间的盲注技术。"
            "所有数据库查询必须使用参数化语句或预编译语句。"
            "正确使用 ORM 框架（SQLAlchemy、Django ORM）可提供自动参数化保护。"
        ),
        "remediation": (
            "1. 对所有数据库操作使用参数化查询/预编译语句。"
            "2. 按字段类型使用白名单模式进行严格的输入验证。"
            "3. 使用 WAF（Web 应用防火墙）过滤已知的 SQL 注入模式。"
            "4. 每个服务使用最小权限数据库账户。"
            "5. 定期进行动态应用安全测试（DAST）。"
        ),
        "category": "policy",
        "source_type": "security_policy",
        "tags": ["sql_injection", "injection", "owasp_top_10", "database"],
        "severity": "CRITICAL",
        "affected_endpoints": ["*"],
        "effectiveness_score": 0.90,
        "confidence": 0.95,
    },
    {
        "title": "目录遍历防护",
        "content": (
            "目录遍历（路径遍历）攻击使用 ../ 序列或编码变体访问 Web 根目录之外的文件。"
            "攻击者针对接受文件路径、下载参数或资源标识符的端点。"
            "编码变体包括 URL 编码（%2e%2e%2f）、双重编码和基于 Unicode 的绕过尝试。"
        ),
        "remediation": (
            "1. 维护允许的文件路径白名单，拒绝所有其他路径。"
            "2. 使用 os.path.realpath() 规范化所有文件路径，并验证其是否在基目录内。"
            "3. 拒绝包含 ../、..\\ 或任何编码变体的输入。"
            "4. 使用 chroot 监狱或容器文件系统隔离。"
            "5. 通过专用端点提供文件服务，并验证解析后的路径。"
        ),
        "category": "policy",
        "source_type": "security_policy",
        "tags": ["directory_traversal", "path_traversal", "file_access"],
        "severity": "HIGH",
        "affected_endpoints": ["*"],
        "effectiveness_score": 0.85,
        "confidence": 0.90,
    },
    {
        "title": "跨站脚本（XSS）防护",
        "content": (
            "XSS 攻击将客户端脚本注入其他用户查看的网页。三种类型："
            "反射型 XSS（请求中的负载反映在响应中）、存储型 XSS（负载持久化在服务器上）"
            "和基于 DOM 的 XSS（通过 URL 片段进行客户端脚本注入）。"
            "攻击向量包括 <script> 标签、事件处理程序（onerror=）、javascript: URL 和 SVG 注入。"
        ),
        "remediation": (
            "1. 对 HTML、属性、JavaScript、CSS 和 URL 应用上下文相关的输出编码。"
            "2. 设置严格的 Content-Security-Policy（CSP）头。"
            "3. 对内联脚本使用 Content-Security-Policy nonce。"
            "4. 使用白名单方法实施输入净化。"
            "5. 设置 X-Content-Type-Options: nosniff 和 HttpOnly 标志。"
        ),
        "category": "policy",
        "source_type": "security_policy",
        "tags": ["xss", "cross_site_scripting", "injection", "owasp_top_10"],
        "severity": "HIGH",
        "affected_endpoints": ["*"],
        "effectiveness_score": 0.85,
        "confidence": 0.90,
    },
    {
        "title": "未授权访问防护",
        "content": (
            "未授权访问发生在用户未经适当身份验证或授权访问资源时。"
            "常见场景：未经管理员权限访问管理端点、IDOR（不安全的直接对象引用）"
            "用户通过修改 ID 访问其他用户资源，以及通过参数操纵进行权限提升。"
        ),
        "remediation": (
            "1. 实施基于角色的访问控制（RBAC），遵循最小权限原则。"
            "2. 在每次请求中验证 JWT 令牌，包括签名、过期时间和声明。"
            "3. 实施适当的会话管理，使用短寿命令牌和轮换机制。"
            "4. 对细粒度的资源级权限使用基于属性的访问控制（ABAC）。"
            "5. 为所有管理接口启用多因素认证（MFA）。"
        ),
        "category": "policy",
        "source_type": "security_policy",
        "tags": ["unauthorized_access", "authentication", "authorization", "rbac"],
        "severity": "CRITICAL",
        "affected_endpoints": ["*"],
        "effectiveness_score": 0.90,
        "confidence": 0.95,
    },
    {
        "title": "敏感数据泄露防护",
        "content": (
            "敏感数据泄露发生在 API 响应暴露个人身份信息（PII）、"
            "凭据、内部 IP 地址、堆栈跟踪或配置详情时。"
            "常见来源：详细的错误消息、未禁用的调试端点、"
            "过多的响应字段以及记录敏感数据。"
        ),
        "remediation": (
            "1. 实施响应字段过滤：绝不返回 password_hash、ssn 或 credit_card 等字段。"
            "2. 对敏感字段的部分显示应用数据脱敏（如 ****-****-****-1234）。"
            "3. 使用字段级访问控制，按角色限制敏感数据。"
            "4. 在生产环境中禁用调试/堆栈跟踪输出。"
            "5. 实施响应模式验证层。"
        ),
        "category": "policy",
        "source_type": "security_policy",
        "tags": ["sensitive_data_leakage", "data_exposure", "pii", "privacy"],
        "severity": "HIGH",
        "affected_endpoints": ["*"],
        "effectiveness_score": 0.80,
        "confidence": 0.85,
    },
    {
        "title": "命令注入防护",
        "content": (
            "命令注入攻击通过将未经过滤的输入传递给系统调用来执行任意操作系统命令。"
            "常见风险函数：os.system()、subprocess.Popen(shell=True)、exec()、eval()。"
            "攻击者使用 shell 元字符注入命令：;、|、&&、||、$()、反引号。"
        ),
        "remediation": (
            "1. 在 subprocess 调用中避免使用 shell=True；优先使用列表参数而非命令字符串。"
            "2. 使用不调用 shell 的安全 API（如需 shell 调用，使用 shlex.quote）。"
            "3. 使用白名单模式实施严格的输入验证。"
            "4. 以最小 OS 权限运行服务（非 root，尽可能使用只读文件系统）。"
            "5. 将应用程序容器化以限制成功注入的爆炸半径。"
        ),
        "category": "policy",
        "source_type": "security_policy",
        "tags": ["command_injection", "injection", "shell", "os_command"],
        "severity": "CRITICAL",
        "affected_endpoints": ["*"],
        "effectiveness_score": 0.85,
        "confidence": 0.90,
    },
    {
        "title": "SSRF 防护",
        "content": (
            "SSRF 攻击诱使服务器向内部或受限资源发出请求。"
            "攻击者提供指向内部服务（127.0.0.1、10.x.x.x、元数据端点）的 URL，"
            "然后服务器获取这些资源。这可能导致内部网络扫描、云元数据泄露和远程代码执行。"
        ),
        "remediation": (
            "1. 维护服务器可访问的允许外部 URL/协议白名单。"
            "2. 禁用未使用的 URL 协议（file://、dict://、gopher://）。"
            "3. 实施网络分段，防止应用服务器访问内部元数据端点。"
            "4. 在发出请求前验证和净化所有用户提供的 URL。"
            "5. 使用限制重定向跟踪的专用 HTTP 客户端。"
        ),
        "category": "policy",
        "source_type": "security_policy",
        "tags": ["ssrf", "server_side_request_forgery", "internal_network"],
        "severity": "HIGH",
        "affected_endpoints": ["*"],
        "effectiveness_score": 0.80,
        "confidence": 0.85,
    },
    {
        "title": "CSRF 防护",
        "content": (
            "跨站请求伪造（CSRF）诱使已认证用户在已登录的 Web 应用上执行非自愿操作。"
            "攻击者制作恶意页面，利用受害者活跃的会话来触发状态变更请求（POST、PUT、DELETE）。"
        ),
        "remediation": (
            "1. 对所有状态变更请求使用反 CSRF 令牌（同步器令牌模式）。"
            "2. 在会话 Cookie 上设置 SameSite=Strict 或 SameSite=Lax。"
            "3. 对敏感操作验证 Origin 和 Referer 头。"
            "4. 为无状态 CSRF 保护实施双重提交 Cookie 模式。"
            "5. 对敏感操作（密码更改、财务操作）要求重新认证。"
        ),
        "category": "policy",
        "source_type": "security_policy",
        "tags": ["csrf", "cross_site_request_forgery", "session", "authentication"],
        "severity": "MEDIUM",
        "affected_endpoints": ["*"],
        "effectiveness_score": 0.80,
        "confidence": 0.85,
    },
]

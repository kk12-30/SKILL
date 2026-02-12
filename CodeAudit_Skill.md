---
description: AI 驱动的代码安全审计 Skill —— 多智能体协作、防幻觉、覆盖率驱动的完整审计系统
tags: [security, audit, vulnerability, multi-agent, OWASP]
---

# Code-Audit Skill 

> **AI 驱动的代码安全审计系统** —— 集成执行状态机、多智能体协作、防幻觉规则、增量补漏策略、覆盖率自检的完整审计框架。

---

## 一、触发条件

当用户输入包含以下关键词时激活：`代码审计`、`安全审计`、`code audit`、`security audit`、`漏洞扫描`、`vulnerability scan`、`OWASP`

**默认扫描模式**：Standard

---

## 二、核心设计哲学

### 2.1 第一原则：防幻觉 —— 宁可漏报，不可误报

```
[硬规则 H1] 禁止猜测文件路径 → 必须用 Glob/Read 验证文件存在，违反则该发现作废
[硬规则 H2] 禁止编造代码片段 → 必须引用 Read 工具实际输出的代码，违反则该发现作废
[硬规则 H3] 禁止报告未读文件中的漏洞 → 没有 Read 过的文件不得出现在报告中
```

**核心逻辑**：误报伤害远大于漏报。误报让开发团队丧失信任，漏报可通过多轮审计弥补。

### 2.2 第二原则：反确认偏见 —— 方法论驱动

```
[B1] 禁止 "基于之前经验重点关注..." → 每个维度独立评估
[B2] 禁止因 "看起来不太可能" 跳过检查 → 所有激活维度必须完成
[B3] 必须枚举所有敏感操作后逐一验证
[B4] 每维度最多 8 个 Sink 类别上界，防止单维度过度深入
```

### 2.3 第三原则：攻击链思维 —— 漏洞不是孤岛

```
认证绕过(H) + 需认证的SSRF(M) = 未认证SSRF(C)
信息泄露(L) + 密码重置缺陷(M) = 账户接管(C)
IDOR(M) + 批量枚举(L) = 全库数据泄露(H/C)
```

每发现一个漏洞，都要评估与已有发现的组合可能性。最终报告设「攻击链分析」章节。

---

## 三、执行状态机

```
PHASE_1_RECON
    │ Phase 1 完成
    ▼
ROUND_N_RUNNING    ◄────────────────────┐
    │ 所有 Agent 完成                    │
    ▼                                   │
ROUND_N_EVALUATION                      │
    │                                   │
    ├── 覆盖率不足 → NEXT_ROUND ───────►│
    │
    └── 覆盖率达标 + 弹性终止条件满足
            │
            ▼
         REPORT
```

### 弹性终止条件（三问法则）

| # | 问题 | 判断标准 |
|---|------|----------|
| Q1 | 是否还有 Critical/High 维度未覆盖？ | D1-D3 任一未覆盖 → **必须继续** |
| Q2 | 下一轮预期能发现什么？ | 仅 Low/Info → 可停止 |
| Q3 | Token 效率如何？ | 预期发现/turn < 0.1 → 停止 |

**硬性终止条件**：覆盖率 ≥ 8/10 且 D1、D2、D3 全部 ✅。

---

## 四、五阶段审计模型

```
Phase 1: Reconnaissance（侦察）→ Phase 2A: Vulnerability Hunt（自由审计）
  → Phase 2B: Coverage Verification（覆盖率自检）→ Phase 3: Deep Dive（增量补漏）
  → Phase 4: Report（报告生成）
```

### Phase 1：侦察（Reconnaissance）

**目标**：不急着找漏洞，先画地图。攻击面决定 Agent 结构。

#### 1.1 识别技术栈

```
1. Glob 扫描项目根目录 → 识别构建文件 (pom.xml, package.json, go.mod, requirements.txt 等)
2. Read 构建文件 → 提取语言版本、框架版本、数据库驱动、中间件依赖
3. Glob 扫描配置文件 (application.yml, .env, config/ 等)
4. Read 配置文件 → 识别数据库类型、缓存、消息队列
```

输出：`[TECH_STACK] 语言/框架/数据库/中间件/构建工具/依赖管理文件路径`

#### 1.2 枚举攻击面

```
Grep 搜索路由/端点定义:
  Java:    @RequestMapping, @GetMapping, @PostMapping, @RestController
  Python:  @app.route, @api_view, urlpatterns
  Go:      http.HandleFunc, gin.GET/POST
  Node.js: app.get/post, router.get/post
  PHP:     Route::get/post
  C#:      [HttpGet], [HttpPost], [Route]
```

输出：`[ATTACK_SURFACE] API端点数/入口层分布/认证机制/数据源/文件操作端点/外部请求端点`

#### 1.3 发现功能模块

识别高风险功能：文件上传下载、数据导入导出、数据源管理(JDBC URL可控)、用户权限管理、支付订单、外部API集成、定时任务、插件扩展加载。

#### 1.4 确定审计维度与权重

```
[DIMENSION_ACTIVATION]
D1 注入 / D2 认证 / D3 授权 / D4 反序列化 / D5 文件操作
D6 SSRF / D7 加密 / D8 配置 / D9 业务逻辑 / D10 供应链
每个维度标注: 权重(HIGH/MEDIUM/LOW) + 原因
```

权重调整规则：
- 数据平台/BI → D1++ D6++
- 有文件上传 → D5++
- 使用JWT → D2++ D7++
- 有反序列化库 → D4++
- 多租户 → D3++ D9++

#### 1.5 输出 Agent 划分方案

基于攻击面动态生成，不使用固定模板：

```
[AGENT_PLAN] Round 1:
  Agent 1: {维度组合} — {审计方向} (max_turns: N)
  Agent 2: ...
划分依据: {攻击面分析结论}
```

Agent 数量参考：Quick 2-3个, Standard 3-5个, Deep 5-8个。

### Phase 2A：自由审计 + 多智能体并行

**核心理念**：LLM 先自由审计，不受 Checklist 束缚。

Agent 工作流程：
1. 接收维度分配 + Agent 合约
2. Grep 搜索 Sink/Source 模式
3. Read 上下文代码（±20行）
4. 追踪数据流: Source → [Transform₁→...→Transformₙ] → Sink
5. 评估防护/净化
6. turns_used ≥ max_turns-3 时停止探索，产出结构化输出

### Phase 2B：覆盖率自检

用 10 维度覆盖率矩阵做自检（详见第五章）。

### Phase 3：增量补漏（R2+）

R2 不重复 R1，使用跨轮传递结构（详见第七章）。

### Phase 4：报告生成

详见第十一章。

---

## 五、10 维度覆盖率矩阵

| # | 维度 | 关键问题 |
|---|------|----------|
| D1 | **注入** | 用户输入能否到达 SQL/Cmd/LDAP/SSTI/SpEL 执行点？ |
| D2 | **认证** | Token 生成、验证、过期是否完整？会话管理是否安全？ |
| D3 | **授权** | 每个敏感操作是否验证用户归属？是否存在 IDOR？ |
| D4 | **反序列化** | 是否存在不受信数据的反序列化？类加载是否可控？ |
| D5 | **文件操作** | 上传/下载路径是否可控？是否存在路径遍历？ |
| D6 | **SSRF** | 服务端 HTTP 请求的 URL 是否用户可控？ |
| D7 | **加密** | 硬编码密钥？弱算法？不安全随机数？ |
| D8 | **配置** | 调试接口暴露？CORS 过宽？敏感信息泄露？ |
| D9 | **业务逻辑** | 竞态条件？流程可跳过？Mass Assignment？ |
| D10 | **供应链** | 依赖是否有已知 CVE？是否使用已弃用库？ |

覆盖状态：✅ 已覆盖（读代码+追数据流）/ ⚠️ 浅覆盖（仅Grep）/ ❌ 未覆盖

**终止条件**：覆盖率 ≥ 8/10 且 D1+D2+D3 全部 ✅。

---

## 六、Agent 合约（Agent Contract）

每个 Agent 启动前自动注入，不可违反：

```
---Agent Contract---
1. 搜索路径: {paths}。排除: node_modules, .git, build, dist, test, __pycache__, vendor, target
2. 必须使用 Grep/Glob/Read 工具。禁止 Bash 中 grep/find/cat（性能退化10-100倍）。
3. 工具调用 ≤50 次，Bash ≤10 次。max_turns: {N}。
4. ★ Turn 预留: turns_used ≥ max_turns-3 时立即停止探索，产出结构化输出。
5. 搜索策略: Grep 定位行号 → Read offset/limit 读上下文（±20行）。禁止读整个大文件(>500行)。
6. 输出: 按结构化模板返回。禁止返回大段原始代码（>3行）。
7. 同类漏洞 ≥5 个合并报告。同 pattern 多文件列清单不逐个深挖。
8. Sink 类别上界: 每维度最多 8 个 Sink 类别，每类最多深追 3 个实例。
9. 数据转换管道追踪: Source → [Transform₁→...→Transformₙ] → Sink，每个Sink至少追踪3层调用链。
10. ★ 截断防御: HEADER 在最前（≤400字），AGENT_OUTPUT_END 在最后。
---End Contract---
```

### 6.1 Turn 预留规则

```
问题: Agent 最后 turn 还在 Grep → turn 耗尽 → 输出截断 → 发现全丢
方案: turns_used ≥ max_turns-3 → 停止探索 → 整理发现 → 输出结构化结果
```

### 6.2 截断防御

```
输出结构:
  ===AGENT_OUTPUT_HEADER===  ← 最前（≤400字，含覆盖率/统计/传递数据）
  ===END_HEADER===
  发现列表（详细内容）
  ===AGENT_OUTPUT_END===     ← 最后（哨兵）

检测: 哨兵丢失 → 输出被截断 → 从 HEADER 提取元数据 → R2 决策不受影响
```

### 6.3 数据转换管道追踪

```
错误（仅看两端）: Controller → DAO  ← 看起来安全
正确（追踪管道）:
  Controller.bindData()
    → DataService.buildQuery()
      → QueryProvider.buildSQL()
        → String.format("SELECT %s FROM %s", fields, tableName) ← SQL注入！

规则: 每个 Sink 至少追踪 3 层: Controller → Service/Manager → Builder/Provider → DAO/Driver
```

---

## 七、增量补漏策略（R2+ 轮次）

### 7.1 跨轮传递结构

R1 完成后，主线程汇总所有 Agent 输出，产出结构化传递数据：

```
===CROSS_ROUND_TRANSFER===
COVERED:  D1(✅ {N}个发现), D2(✅ {N}个), D3(✅ {N}个), ...
GAPS:     D4(❌ 未覆盖), D9(❌ 未覆盖), D1(⚠️ SQL查询构建层未深入)
CLEAN:    [JNDI/XXE/Fastjson — 已搜索确认不存在的攻击面]
HOTSPOTS: [QueryBuilder.java:135 — 字符替换未追踪, PermissionManager.java — 鉴权逻辑待验证]
FILES_READ: [TokenUtils.java:JWT decode无verify, CryptoUtils.java:硬编码AES密钥, ...]
GREP_DONE: [JWT.decode, @Permission, CREATE ALIAS, loadRemoteFile, ...]
===END_TRANSFER===
```

### 7.2 R2 Agent 约束规则

传递结构注入每个 R2 Agent 上下文，附带约束：

```
[R2-RULE-1] 禁止重读: FILES_READ 中已分析过的文件不得再次 Read
            （除非 HOTSPOTS 明确要求对该文件特定区域深入）
[R2-RULE-2] 禁止重复搜索: GREP_DONE 中已执行过的搜索模式不得再次 Grep
[R2-RULE-3] 跳过已清洁方向: CLEAN 中已确认不存在的攻击面直接跳过
[R2-RULE-4] 优先深入热点: HOTSPOTS 是 R2 首要目标
[R2-RULE-5] 聚焦未覆盖维度: GAPS 中 ❌ 是必须覆盖的目标，⚠️ 需加深
```

### 7.3 R2 Agent 数量自适应

| 缺口状态 | R2 Agent 数量 | 每 Agent turns |
|----------|--------------|----------------|
| ❌ 未覆盖 0-1 个 | 1 Agent | 20 |
| ❌ 未覆盖 2-3 个 | 2 Agent | 2×20 |
| ❌ 未覆盖 4+ 个 | 3 Agent | 3×20 |
| ⚠️ 浅覆盖需加深 | +1 Agent | +20 |
| HOTSPOTS ≥ 3 个 | +1 Agent | +20 |

**效率目标**：R2 Token ≤ R1 的 1.5 倍，覆盖率提升到 10/10。

---

## 八、两层检查清单

**理念：Checklist 不驱动审计，而是验证覆盖。**

```
LLM 先自由审计（Phase 2A）→ 再用矩阵查漏（Phase 2B）
原因: LLM 优势在于联想和推理，过度依赖 checklist 会将模型降级为模式匹配引擎。
```

**Layer 1：覆盖率矩阵**（Phase 2B 加载）
- 10 个安全维度覆盖率检查
- 验证 Phase 2A 是否有遗漏
- 不含具体检测规则

**Layer 2：语言语义提示**（仅对未覆盖维度按需加载）
- 9 种语言各自独立的语义提示
- 只有 Phase 2B 发现某维度未覆盖时才加载
- 好处: 不浪费Token / 不限制模型 / 不遗漏维度

---

## 九、置信度分级标准

| 等级 | 符号 | 条件 | 可报告最高严重度 |
|------|------|------|-----------------|
| **已验证** | `[V]` | 完整数据流 + 无有效防护 + 可构造PoC | Critical |
| **高置信** | `[HC]` | 完整数据流 + 无有效防护，PoC需特定环境 | Critical/High |
| **中置信** | `[MC]` | 数据流不完整，或防护可绕过性不确定 | Medium |
| **需验证** | `[NV]` | 仅Grep命中模式，未追踪数据流 | Low/Info |

### 硬性规则

```
[RULE-CS-1] Critical 必须达到 [V] 或 [HC]
  → 需有完整数据流: Source → [Transform...] → Sink
  → 需确认无有效净化/过滤，违反则降级为 Medium

[RULE-CS-2] High 必须达到 [HC] 或以上
  → 需有完整数据流，违反则降级为 Medium

[RULE-CS-3] 仅 Grep 命中的发现最高报告为 Low/Info
  → 未追踪数据流不得标 Medium 及以上
```

---

## 十、语言模块语义提示

**按需加载**：仅在 Phase 2B 发现对应维度未覆盖时加载对应语言段落。

### 10.1 Java

```
[D1 注入]
Sink: Statement.execute(), PreparedStatement拼接, MyBatis ${}, String.format()拼SQL,
      Runtime.exec(), ProcessBuilder, ExpressionParser.parseExpression()(SpEL),
      DirContext.search()(LDAP), 模板引擎用户输入(Thymeleaf/Freemarker/Velocity)
Source: @RequestParam, @RequestBody, @PathVariable, HttpServletRequest.getParameter()
Grep: "execute(", "${", "String.format", "Runtime.exec", "ProcessBuilder",
      "parseExpression", "DirContext.search"

[D2 认证]
检查: JWT.decode()是否有verify(), JWT密钥是否硬编码(secretKey/signingKey/JWT_SECRET),
      Session fixation, 密码重置Token时效性
Grep: "JWT.decode", "secretKey", "signingKey", "authFilter", "SecurityConfig"

[D3 授权]
检查: @PreAuthorize/@Secured/@RolesAllowed 注解的AOP实现, 自定义权限注解切面,
      IDOR(资源ID从用户输入获取不验证归属)
Grep: "@Permission", "hasRole", "hasAuthority", "AccessDecisionManager"

[D4 反序列化]
Sink: ObjectInputStream.readObject(), XMLDecoder.readObject(),
      Jackson enableDefaultTyping, Fastjson autoType, RMI/JNDI lookup()
Grep: "readObject", "deserialize", "fromJson", "autoType", "ObjectMapper",
      "enableDefaultTyping", "InitialContext.lookup"

[D5 文件操作]
Sink: new File(userInput), Paths.get(userInput), FileOutputStream/InputStream路径来自用户,
      MultipartFile上传(文件名/路径/类型), ZipSlip(entry.getName()含../)
Grep: "upload", "download", "getOriginalFilename", "transferTo", "FileCopyUtils",
      "ZipEntry", "entry.getName"

[D6 SSRF]
Sink: new URL(userInput).openConnection(), HttpURLConnection, HttpClient,
      RestTemplate, WebClient, JDBC URL用户可控
Grep: "new URL(", "openConnection", "httpClient.execute", "restTemplate",
      "WebClient.create", "DriverManager.getConnection"

[D7 加密]
检查: 硬编码密钥(key=", secretKey="), 弱算法(MD5/SHA1用于密码, DES, RC4),
      不安全随机数(java.util.Random), ECB模式
Grep: "Cipher.getInstance", "MessageDigest", "SecretKeySpec", "new Random()",
      "AES/ECB", "DES", "MD5", "SHA-1"

[D8 配置]
检查: Actuator端点(/actuator/env, /actuator/heapdump), CORS(allowedOrigins("*")),
      Debug模式, Swagger暴露, H2 Console
Grep: "actuator", "cors", "allowedOrigins", "debug", "swagger", "h2-console",
      "management.endpoints"

[D9 业务逻辑]
检查: HashMap非线程安全(应ConcurrentHashMap), TOCTOU竞态,
      Mass Assignment(@RequestBody直接绑实体无@JsonIgnore), 流程跳步, 金额负数/溢出
Grep: "synchronized", "ConcurrentHashMap", "HashMap", "@RequestBody",
      "BeanUtils.copyProperties", "volatile"

[D10 供应链]
操作: Read pom.xml/build.gradle → 提取依赖版本
重点CVE: Log4j, Spring4Shell, Fastjson, Jackson-databind, Commons-Collections
Grep: "log4j", "fastjson", "commons-collections", "jackson-databind", "spring-core"
```

### 10.2 Python

```
[D1] Sink: cursor.execute(f"..."), os.system(), subprocess.Popen(shell=True),
     eval(), exec(), __import__(), pickle.loads(), yaml.load()
     Source: request.args, request.form, request.json, sys.argv
[D2] jwt.decode(verify=False), SECRET_KEY硬编码, @login_required遗漏
[D3] IDOR(object.get(id=request.args['id'])), 装饰器覆盖率, permission_classes
[D4] pickle.loads(), yaml.unsafe_load(), shelve.open(), marshal.loads(), jsonpickle
[D5] open(user_path), os.path.join(base,user_input), send_file(), zipfile.extractall()
[D6] requests.get(user_url), urllib.request.urlopen(), httpx, aiohttp
[D7] hashlib.md5/sha1密码哈希, random.random()安全场景, 硬编码SECRET_KEY
[D8] DEBUG=True, ALLOWED_HOSTS=['*'], CORS_ALLOW_ALL_ORIGINS
[D9] race condition(无锁共享状态), 流程跳步, 金额校验
[D10] Read requirements.txt/Pipfile → 检查CVE
```

### 10.3 Go

```
[D1] Sink: db.Query(fmt.Sprintf("...%s...",input)), exec.Command(input), template.HTML(input)
     Source: r.URL.Query(), r.FormValue(), r.Body, gin.Context.Query/Param
[D2] JWT库用法, token验证完整性, session管理
[D3] 中间件覆盖率, IDOR, 权限检查
[D4] gob.Decode, json.Unmarshal(接口类型), encoding/xml
[D5] os.Open(userPath), filepath.Join(base,input), io.Copy, archive/zip
[D6] http.Get(userURL), http.NewRequest+用户可控URL
[D7] crypto/rand vs math/rand, 硬编码密钥
[D8] pprof暴露, CORS, 调试端点
[D9] goroutine竞态(无mutex), channel误用
[D10] Read go.sum → 检查CVE
```

### 10.4 PHP

```
[D1] Sink: mysqli_query("...$_GET['id']..."), system(), exec(), passthru(),
     eval(), preg_replace('/e'), include($_GET['page'])
     Source: $_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, php://input
[D2] session_regenerate_id(), 密码比较(==vs===), token验证
[D3] IDOR, 中间件覆盖, ACL实现
[D4] unserialize($_GET['data']), __wakeup(), __destruct()链
[D5] move_uploaded_file(), file_get_contents($userPath), include/require路径注入
[D6] file_get_contents($userURL), curl_exec(), fopen($userURL)
[D7] md5()密码, rand()安全场景, 硬编码密钥
[D8] display_errors=On, expose_php, phpinfo()
[D9] 竞态, 流程跳步, 类型混淆
[D10] Read composer.json → 检查CVE
```

### 10.5 JavaScript / Node.js

```
[D1] Sink: eval(), child_process.exec(), new Function(), vm.runInContext(),
     SQL拼接(sequelize.query, knex.raw)
     Source: req.query, req.body, req.params, req.headers
[D2] jwt.verify vs jwt.decode, secret硬编码, session管理(express-session)
[D3] 中间件覆盖率, IDOR, express middleware auth
[D4] node-serialize, js-yaml.load(), 原型污染(__proto__, constructor.prototype)
[D5] fs.readFile(userPath), path.join(base,input), multer配置, res.download()
[D6] axios.get(userURL), node-fetch(userURL), http.request
[D7] crypto.createHash('md5'), Math.random()安全场景, 硬编码JWT_SECRET
[D8] NODE_ENV=development, CORS配置, express.static('/')
[D9] 原型污染(对象合并), race condition(异步), 参数污染
[D10] Read package.json → npm audit, 检查CVE
```

### 10.6 C# / .NET

```
[D1] Sink: SqlCommand(string.Format(...)), Process.Start(), Razor动态编译
     Source: Request.Query, Request.Form, [FromBody], [FromQuery]
[D2] JWT验证, Identity框架配置, Cookie认证
[D3] [Authorize]覆盖率, Policy-based auth, IDOR
[D4] BinaryFormatter.Deserialize(), JsonConvert.DeserializeObject(TypeNameHandling)
[D5] System.IO.File操作, IFormFile, Path.Combine
[D6] HttpClient.GetAsync(userURL), WebRequest.Create
[D7] MD5/SHA1, RNGCryptoServiceProvider vs Random, 硬编码密钥
[D8] launchSettings.json, CORS, Swagger, 调试中间件
[D9] 竞态, Mass Assignment(无[Bind]保护), 流程跳步
[D10] Read *.csproj → NuGet包CVE
```

### 10.7 Ruby

```
[D1] Sink: ActiveRecord find_by_sql(拼接), system(), exec(), `cmd`,
     ERB::new(user_input).result, send(user_input)
     Source: params[], request.body
[D2] Devise配置, session管理, remember_me token
[D3] CanCanCan/Pundit覆盖率, IDOR, before_action :authorize
[D4] Marshal.load, YAML.load(不安全), JSON.parse(create_additions)
[D5] File.open(params[:path]), send_file, Paperclip/CarrierWave
[D6] open-uri(用户URL), Net::HTTP, HTTParty
[D7-D10] 参考通用模式 + Gemfile依赖CVE
```

### 10.8 C / C++

```
[D1] Sink: sprintf/printf格式化字符串, system(), exec*(), popen(),
     strcpy/strcat/gets(缓冲区溢出), SQL拼接
     Source: argv, stdin, recv(), getenv()
[D2] 认证逻辑实现, 密码存储, session token
[D3] 权限检查(setuid), 文件权限, 内存越界读(信息泄露)
[D4] 反序列化(自定义协议), 类型混淆
[D5] fopen/open路径注入, 符号链接攻击, 目录遍历
[D6] connect()/socket相关, libcurl
[D7] 弱随机(rand/srand), 硬编码密钥, 不安全加密
[D8] 编译选项(-fno-stack-protector), ASLR/PIE, 调试符号
[D9] 整数溢出, UAF, 双重释放, 竞态条件
[D10] 第三方库版本CVE
```

### 10.9 Rust

```
[D1] Sink: unsafe块中的裸指针操作, Command::new(user_input),
     SQL拼接(sqlx::query!宏外的手动拼接)
     Source: web框架请求参数(actix-web, axum, rocket)
[D2] JWT验证, session管理, 认证中间件
[D3] 授权中间件覆盖, IDOR
[D4] serde反序列化(不受信来源), bincode
[D5] std::fs操作(用户路径), 路径遍历
[D6] reqwest::get(user_url), hyper客户端
[D7] 弱随机(rand但未用OsRng), 硬编码密钥
[D8] 调试配置, CORS
[D9] unsafe块中的竞态, 逻辑错误
[D10] Read Cargo.toml → cargo audit
```

---

## 十一、Agent 结构化输出模板

每个 Agent 必须严格按以下模板输出结果：

```
===AGENT_OUTPUT_HEADER===
agent_id: {Agent-R{round}-{seq}}
dimensions: [D{x}, D{y}, ...]
coverage: {Dx: ✅|⚠️|❌, Dy: ✅|⚠️|❌, ...}
findings_count: {N}
critical: {N}  high: {N}  medium: {N}  low: {N}  info: {N}
files_read: [
  {file1} — {关键发现摘要},
  {file2} — {关键发现摘要},
  ...
]
grep_patterns: [{pattern1}, {pattern2}, ...]
hotspots: [
  {file:line — 未展开的高风险点描述},
  ...
]
clean: [{已确认不存在的攻击面}]
turns_used: {N}/{max_turns}
tool_calls: {N}/50
===END_HEADER===

## 发现列表

### [{severity}] Finding-{agent_id}-{seq}: {漏洞标题}
- **CVSS**: {score}
- **置信度**: [V] | [HC] | [MC] | [NV]
- **维度**: D{x} ({维度名称})
- **位置**: `{file_path}:{line_number}`
- **代码证据**:
  ```{lang}
  // {file_path}:{start_line}-{end_line}
  {Read 工具实际输出的关键代码，≤3行}
```
- **数据流**:
  ```
  Source: {入口点描述} ({file}:{line})
    → Transform₁: {中间处理} ({file}:{line})
    → Transform₂: {中间处理} ({file}:{line})
    → Sink: {危险操作} ({file}:{line})
  ```
- **防护分析**: {是否存在净化/过滤，效果评估，是否可绕过}
- **利用路径**: {攻击者如何利用此漏洞}
- **攻击链**: {与其他发现的组合可能性，引用 Finding ID}
- **修复建议**: {具体修复方案}

### [同类合并] {漏洞类型} × {N} 个实例
- **模式**: {共同的漏洞模式描述}
- **文件清单**:
  | # | 文件 | 行号 | 具体表现 |
  |---|------|------|----------|
  | 1 | {file1} | {line} | {描述} |
  | 2 | {file2} | {line} | {描述} |
  | ... | | | |
- **统一修复建议**: {通用修复方案}

===AGENT_OUTPUT_END===
```

---

## 十二、最终报告输出模板

所有轮次完成后，主线程汇总生成最终报告：

```markdown
# 安全审计报告

## 1. 执行摘要

| 指标 | 数据 |
|------|------|
| 项目 | {项目名称} |
| 代码量 | {行数} |
| 技术栈 | {语言 + 框架 + 数据库} |
| 审计模式 | {Quick/Standard/Deep} |
| 审计轮次 | {N} 轮, {M} 个 Agent |
| 工具调用 | {总 turns} 次 |
| 覆盖率 | {X}/10 维度 |
| 发现总数 | {total} (Critical:{c}, High:{h}, Medium:{m}, Low:{l}, Info:{i}) |

### 风险评级: {Critical / High / Medium / Low}

## 2. 关键发现（Critical + High）

按严重度降序排列，每个发现包含完整数据流和利用路径。

### C-{seq}: {漏洞标题} [CVSS {score}]
- 置信度: {[V]/[HC]}
- 维度: D{x}
- 位置: `{file}:{line}`
- 数据流: Source → ... → Sink（完整链路）
- 影响: {业务影响描述}
- 利用条件: {前置条件}
- 修复建议: {具体方案}

## 3. 攻击链分析

展示多漏洞串联的端到端攻击路径：

### Chain {seq}: {攻击链名称} [综合 CVSS {score}]
```
{漏洞1}({severity}) → {漏洞2}({severity}) → {最终影响}
```
- 前置条件: {攻击者需要的初始条件}
- 攻击步骤:
  1. {步骤1}: 利用 {Finding-ID} ...
  2. {步骤2}: 利用 {Finding-ID} ...
  3. {步骤3}: 达成 {最终目标}
- 影响: {端到端影响}
- 缓解: {阻断攻击链的最优修复点}

## 4. 覆盖率矩阵

| # | 维度 | 状态 | 发现数 | 说明 |
|---|------|------|--------|------|
| D1 | 注入 | ✅ | {N} | {审计深度描述} |
| D2 | 认证 | ✅ | {N} | {审计深度描述} |
| ... | | | | |
| D10 | 供应链 | ✅ | {N} | {审计深度描述} |

## 5. 全部发现列表

按维度分组，包含所有严重度的发现。

### D{x}: {维度名称} ({N} 个发现)

| # | 严重度 | 置信度 | 标题 | 位置 | CVSS |
|---|--------|--------|------|------|------|
| 1 | Critical | [V] | {标题} | {file:line} | {score} |
| 2 | High | [HC] | {标题} | {file:line} | {score} |
| ... | | | | | |

## 6. 修复优先级建议

| 优先级 | 发现 | 修复方案 | 预估工作量 |
|--------|------|----------|-----------|
| P0 (立即) | {Critical 漏洞} | {方案} | {天数} |
| P1 (本周) | {High 漏洞} | {方案} | {天数} |
| P2 (本月) | {Medium 漏洞} | {方案} | {天数} |
| P3 (计划) | {Low 漏洞} | {方案} | {天数} |

## 7. 审计过程记录

### Round 1
| Agent | 方向 | turns | 发现数 |
|-------|------|-------|--------|
| Agent 1 | {维度+方向} | {N} | {N} |
| ... | | | |
| R1 合计 | | {total_turns} | {total_findings} |

覆盖率评估: {X}/10

### Round 2（如有）
| Agent | 方向 | turns | 新发现 |
|-------|------|-------|--------|
| R2-Agent 1 | {方向} | {N} | {N} |
| ... | | | |

覆盖率: {X}/10

## 8. 免责声明

本报告基于 AI 辅助的静态代码分析，不替代人工渗透测试。
所有 Critical/High 级别发现已追踪完整数据流并评估置信度，
但建议对关键发现进行人工验证和动态测试确认。
```

---

## 十三、安全域模块（按需加载）

| 模块 | 加载条件 | 核心检查点 |
|------|----------|-----------|
| **API Security** | 项目有 REST/GraphQL API | 认证绕过、批量查询、深度限制、速率限制、过度数据暴露 |
| **LLM Security** | 项目集成 AI/ML | Prompt 注入、模型投毒、敏感数据泄露到模型、不安全输出处理 |
| **Race Conditions** | 有并发操作场景 | TOCTOU、双花攻击、并发资源竞争、锁粒度不足 |
| **Cryptography** | 有加密/签名/JWT | 密钥管理、算法选择、IV/Nonce 重用、填充预言、时序攻击 |

### API Security 模块详细检查

```
1. 认证: API Key 泄露, Bearer Token 验证, OAuth 配置
2. 授权: 对象级(BOLA/IDOR), 功能级, 字段级
3. 输入: 批量查询限制(GraphQL depth/complexity), 参数污染
4. 输出: 过度数据暴露(返回了不需要的敏感字段)
5. 速率: 暴力破解防护, API 限流
6. 日志: 安全事件是否记录, 敏感数据是否在日志中
```

### LLM Security 模块详细检查

```
1. Prompt 注入: 用户输入是否直接拼接到 system prompt
2. 不安全输出: LLM 输出是否被当作代码/命令执行
3. 数据泄露: 训练数据/上下文中是否包含敏感信息
4. 过度授权: LLM Agent 是否拥有过多系统权限
5. 模型 DoS: 恶意输入导致资源耗尽
```

---

## 十四、模块化知识库架构

```
code-audit-skill/
├── core/                          # 核心模块（始终可用）
│   ├── anti-hallucination.md      # 防幻觉规则和验证流程
│   ├── taint-analysis.md          # 污点分析和数据流追踪模板
│   ├── poc-generation.md          # PoC 验证模板生成
│   └── capability-baseline.md     # 防止能力退化的回归测试框架
│
├── languages/                     # 语言模块（按技术栈加载）
│   ├── java.md                    # Java D1-D10 语义提示
│   ├── python.md
│   ├── go.md
│   ├── php.md
│   ├── javascript.md
│   ├── csharp.md
│   ├── ruby.md
│   ├── cpp.md
│   └── rust.md
│
├── domains/                       # 安全域模块（按需加载）
│   ├── api-security.md
│   ├── llm-security.md
│   ├── race-conditions.md
│   └── cryptography.md
│
└── templates/                     # 输出模板
    ├── agent-output.md            # Agent 结构化输出模板
    ├── report-standard.md         # Standard 模式报告模板
    ├── report-quick.md            # Quick 模式精简报告
    └── cross-round-transfer.md    # 跨轮传递结构模板
```

### 核心模块说明

| 模块 | 功能 | 加载时机 |
|------|------|----------|
| **Anti-Hallucination** | H1/H2/H3 硬规则 + 违反检测 + 发现作废流程 | 始终加载 |
| **Taint Analysis** | Source/Transform/Sink 追踪模板 + 净化检测 | 始终加载 |
| **PoC Generation** | 针对各漏洞类型的 PoC 模板框架 | Deep 模式加载 |
| **Capability Baseline** | 用历史审计结果做回归测试，确保迭代不退化 | 可选加载 |

---

## 十五、与传统 SAST 工具对比

| 维度 | 传统 SAST (Semgrep/SonarQube) | code-audit Skill |
|------|-------------------------------|-----------------|
| 检测方式 | 固定规则模式匹配 | LLM 语义理解 + 数据流追踪 |
| 数据流追踪 | 有限（1-2 跳） | 深度（3+ 跳，含中间转换层） |
| 业务逻辑漏洞 | 几乎无法检测 | 可检测（D9 维度） |
| 误报率 | 较高（20-40%） | 较低（防幻觉规则约束） |
| 攻击链分析 | 无 | 支持多漏洞串联 |
| 上下文理解 | 无（逐文件） | 有（跨文件、跨模块推理） |
| 可解释性 | 规则 ID + 代码位置 | 完整数据流 + 利用路径 + PoC |
| 运行成本 | 低（本地执行） | 较高（LLM API） |
| 新漏洞模式 | 需手动添加规则 | 可基于上下文推理发现 |

**互补策略**：Phase 1 如检测到 Semgrep 可用，先跑 Semgrep 作为基线，再做深度分析。

---

## 附录 A：Skill 文档编写防坑指南

```
1. 单一权威来源: 每条规则只在一处完整定义，其他地方引用
2. 环境感知: 规则必须说明适用条件和边界
3. 异常路径完整性: 每个决策点都必须有 "否则" 分支
4. 层级标注: 硬规则(不可违反) vs 软规则(有条件例外)
5. 模板即合约: Agent 输出模板就是行为约束
6. 废弃标记: 被替代的规则必须显式删除或标记废弃
7. 版本追踪: 重大变更记录版本号和变更原因
```

---

## 附录 B：常见陷阱与修复

| # | 陷阱 | 表现 | 修复 |
|---|------|------|------|
| 1 | Agent 输出截断 | 发现全丢 | Turn 预留 + HEADER 前置 + 哨兵 |
| 2 | R2 重复 R1 | Token 浪费 2.5x | 跨轮传递结构 |
| 3 | 幻觉漏洞 | 报告不存在的文件/代码 | H1/H2/H3 硬规则 |
| 4 | 确认偏见 | 单维度过深其他遗漏 | 覆盖率矩阵 + Sink 上界 |
| 5 | Bash 性能退化 | grep/find 比工具慢100x | Agent 合约禁止 Bash 文本搜索 |
| 6 | 大文件一次读取 | Token 浪费 | Grep 定位 + Read offset/limit |
| 7 | 文档冗余矛盾 | 规则冲突 | 单一权威来源原则 |

## 

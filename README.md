# DigiForensics-Wiki

**DigiForensics · 电子取证.com**
数字寻迹，取证求真。

[平台首页](https://www.digiforensics.cn/) · [在线知识库](https://www.digiforensics.cn/wiki) · [文档目录](INDEX.md) · [社区共建](https://www.digiforensics.cn/community) · [CC BY-SA 4.0](LICENSE.md)

DigiForensics-Wiki 是由 DigiForensics 平台维护、面向社区开放协作的电子取证知识库。内容围绕检材获取、数据结构、工具使用、痕迹分析和结果复核展开，供技术学习、取证训练、比赛备赛与研究参考。

本仓库提供 Wiki 的 Markdown 文档和离线检索数据。当前收录 **165 篇公开文档**，覆盖取证基础、磁盘镜像、计算机、移动设备、文件系统、加密数据、服务器、内存及相关技术标准。

*An open digital forensics knowledge base maintained by DigiForensics, with Chinese technical documentation for learning, forensic practice and research.*

## 关于 DigiForensics

[DigiForensics](https://www.digiforensics.cn/) 是面向中文用户的电子取证技术学习平台，整理赛事、题库、训练检材、工具、技术文档和比赛复盘。平台通过 [GitHub 组织](https://github.com/DigiForensics) 发布开源项目，并提供 [社区共建入口](https://www.digiforensics.cn/community)，接受题解、取证知识和实用工具贡献。

Wiki 承担其中的技术参考工作：按知识领域组织方法与工件，说明数据在哪里、如何提取与解析、哪些条件会影响判断。阅读文档后，可结合平台的训练检材和比赛复盘检验所学方法。

## 知识目录

完整条目见 [INDEX.md](INDEX.md)。下表按仓库现有目录列出内容；数据库、网络与容器专题分别收录在对应领域中。

| 领域 | 文档数 | 主要内容 |
| --- | ---: | --- |
| [取证基础与规范](docs/fundamentals/) | 12 | 取证流程、完整性校验、时间戳、保管链、装备、学习路径 |
| [磁盘镜像与仿真](docs/imaging/) | 6 | 镜像采集、证据格式、只读接入、在线取证、虚拟机仿真 |
| [计算机取证](docs/computer/) | 28 | Windows、Linux、macOS 的注册表、日志、执行与用户活动痕迹 |
| [文件系统分析](docs/filesystem/) | 10 | NTFS、FAT/exFAT、ext4、APFS、F2FS、文件雕刻与恢复 |
| [移动取证](docs/mobile/) | 14 | Android、iOS、SIM/USIM、应用数据、SQLite 与数据库分析 |
| [加密与密码取证](docs/crypto/) | 7 | BitLocker、EFS、VeraCrypt、浏览器凭据、配置与数据库加密 |
| [服务器与云取证](docs/server/) | 20 | Web 日志、IIS、Exchange、管理面板、Docker、Kubernetes |
| [内存与专项取证](docs/memory/) | 11 | 内存采集、Volatility、进程与注入检测、网络连接、PCAP |
| [电子数据法律标准](docs/electronic-data-legal-standards/) | 50 | SF/T、SF/Z JD、GB/T 等电子数据及相关鉴定技术标准 |
| [其他专题](docs/general/) | 7 | PVE/Ceph、鸿蒙、应用数据、手机删除痕迹与运动软件 |
| **合计** | **165** | |

## 从哪里开始

- **学习基础**：从 [取证技能树与学习路径](docs/fundamentals/fundamentals-process/fundamentals-process-forensics-learning-path.md) 和 [五阶段流程与基本原则](docs/fundamentals/fundamentals-process/fundamentals-process-five-stage-forensics-process.md) 开始，再学习镜像、文件系统和操作系统工件。
- **分析具体检材**：先识别设备、系统版本、检材来源和获取方式，再从 [文档目录](INDEX.md) 进入对应领域。Windows、Linux、macOS、Docker 与 Kubernetes 均有工件地图，可用于整理检查清单。
- **查询具体技术**：按工具、文件名、字段或格式搜索，例如 `Frida`、`SRUM`、`$MFT`、`SQLite WAL`。同时阅读该主题的适用条件、常见陷阱与验证方法。
- **查找标准**：进入 [电子数据法律标准](docs/electronic-data-legal-standards/)，按标准号或题名定位。精确引用与版本有效性核对以发布机构的原始文件为准。

## 阅读与离线使用

在线阅读可使用 [平台 Wiki](https://www.digiforensics.cn/wiki) 的知识树和搜索功能。在 GitHub 中可直接打开 Markdown 文档，也可以克隆到本地：

```sh
git clone https://github.com/DigiForensics/DigiForensics-Wiki.git
cd DigiForensics-Wiki
```

阅读 Markdown 无需部署网站。站内文章链接使用相对路径，正文保留 `section-N` 锚点；外部参考资料链接保留原地址。

安装 `ripgrep` 后，可检索正文：

```sh
# 按主题查找
rg -n '注册表|SQLite|Frida' docs/

# 按文件名或字段查找；固定字符串模式不会把 $ 或 . 当成正则语法
rg -n -F '$MFT' docs/
rg -n -F 'SRUDB.dat' docs/
```

## 仓库结构与检索数据

```text
DigiForensics-Wiki/
├── README.md                  项目介绍与阅读入口
├── INDEX.md                   全部文档目录
├── docs/                      按领域组织的 Markdown 正文
├── data/
│   ├── knowledge-index.jsonl  文档元数据与 SHA-256
│   └── chunks.jsonl           按标题切分的正文片段
├── manifest.json              文档数量与索引生成时间
├── LICENSE                    CC BY-SA 4.0 许可全文
├── LICENSE.md                 许可说明
└── NOTICE.md                  来源与署名说明
```

正文是内容维护的依据。两个 JSONL 文件便于离线检索和构建资料索引；当前包含 165 条文档记录、5,725 个正文片段。处理片段时应保留 `article_id`、`path`、`title`、`canonical` 和 `license`，引用时回到完整文章确认上下文。

每篇文档的 front matter 记录来源信息：

| 字段 | 含义 |
| --- | --- |
| `title`、`slug` | 文章标题与原站条目标识 |
| `author` | 原文作者或署名主体 |
| `canonical` | 原站文章地址 |
| `updated_at` | 原站记录的文章更新时间 |
| `license` | 该条目的许可标识，第三方材料仍须保留原权利声明 |
| `source_url`、`references` | 已记录的来源或参考链接；未记录时可能为空 |
| `category`、`space`、`node_path` | 分类与知识树位置 |

GitHub 修订记录见 [提交历史](https://github.com/DigiForensics/DigiForensics-Wiki/commits/main/)；`updated_at` 保留原站时间。`manifest.json` 的 `generated_at` 表示检索数据生成时间。网站与仓库分别更新，内容可能存在版本差异。

## 内容维护原则

技术文档应围绕具体检材、数据结构和可复核的方法展开：

- **说明前提**：标注相关系统、工具或格式版本，区分在线采集、离线分析及需要授权的操作。
- **保留依据**：结论能够对应到文件路径、字段、偏移、日志或复现步骤，引用资料能够追溯到原出处。
- **说明判断范围**：区分直接观察、关联推断与尚未验证的内容；“未发现”应说明检查范围和限制。
- **用技术事实表达**：直接说明操作与结果，避免宣传性措辞、无依据的准确率和绝对化承诺。
- **维护来源**：保留原作者、来源链接、许可及第三方声明，注明实质修改。

命令与代码需结合实际环境使用。案例中的示例文件名和脱敏数据不能作为真实案件的事实依据。标准类资料保留原文表达，不套用技术教程的写作格式；引用前核对原始文件、版本和适用范围。

## 参与共建

可通过 [Issues](https://github.com/DigiForensics/DigiForensics-Wiki/issues) 报告错误、提出补充建议，或提交 [Pull Request](https://github.com/DigiForensics/DigiForensics-Wiki/pulls) 修正文档。

提交技术问题时，请提供文章路径、具体段落、系统与工具版本，以及预期和实际结果。附上复现步骤或官方资料链接，便于核查；示例数据请先脱敏。

提交文档修订时，请：

1. 先检查已有条目，在对应领域补充或修正，避免重复文章。
2. 说明修改解决的具体问题，保留必要的验证步骤与适用条件。
3. 保留署名、来源和许可；新增第三方资料时注明出处及使用范围。
4. 检查相对链接、页内锚点和代码围栏；修改正文后同步更新检索数据中的片段与校验值。
5. 确认提交中没有真实检材、数据库导出、账号记录、凭据、环境配置或个人工作文件。

平台题解、检材和工具等内容，也可通过 [社区共建](https://www.digiforensics.cn/community) 提交。

## 许可与引用

本仓库的原创文档及社区整理内容采用 **[CC BY-SA 4.0（署名—相同方式共享 4.0 国际）](LICENSE.md)**。复制、分发或改编时，请保留署名、原文链接和许可声明，注明修改；改编成果采用相同许可发布。许可全文见 [LICENSE](LICENSE)。

引用的法律、标准和第三方资料保留原出处的许可与权利声明，见各篇文档及 [NOTICE.md](NOTICE.md)。本仓库许可不替代第三方许可，也不覆盖平台其他题库、检材、题解或资源的使用条款。

引用格式：

```text
作者：《文章标题》，DigiForensics Wiki，原文地址。
原文更新时间：YYYY-MM-DD；许可：CC BY-SA 4.0。
如有改编，补充修改说明及所使用的 Git 提交版本。
```

## 联系与反馈

- 文档问题与建议：[GitHub Issues](https://github.com/DigiForensics/DigiForensics-Wiki/issues)
- 平台入口：[www.digiforensics.cn](https://www.digiforensics.cn/)
- 开源项目：[DigiForensics GitHub](https://github.com/DigiForensics)
- 社区交流：[社区共建](https://www.digiforensics.cn/community) · QQ 群 **1078049831**
- 平台反馈与版权问题：[feedback@digiforensics.cn](mailto:feedback@digiforensics.cn)

# DigiForensics-Wiki

数字取证参考知识库，收录取证基础、文件系统、计算机、移动设备、服务器、内存、加密数据和电子数据相关标准，共 165 篇文档。

- 在线阅读：[DigiForensics Wiki](https://www.digiforensics.cn/wiki)
- 文档目录：[INDEX.md](INDEX.md)
- 仓库地址：[DigiForensics/DigiForensics-Wiki](https://github.com/DigiForensics/DigiForensics-Wiki)

## 阅读与检索

`docs/` 按领域分类，可直接在 GitHub 或本地 Markdown 阅读器中浏览。站内文章链接使用本地相对路径，外部资料保留原链接。

```sh
rg -n "注册表|SQLite|Frida" docs/
```

`data/knowledge-index.jsonl` 保存文档元数据及 SHA-256；`data/chunks.jsonl` 保存按标题切分的正文片段，可用于离线检索。`manifest.json` 记录文档数量与索引生成时间。

文章中的命令和代码是操作示例，使用时需确认系统版本、工具版本和检材状态。法律与标准类文档保留引用内容，使用前请核对发布机构公布的版本及适用范围。

## 参与维护

欢迎通过 Issue 报告错误，或提交 Pull Request 修正文档。技术修订请附对应系统与工具版本、复现步骤或官方资料链接；引用第三方内容时保留来源和权利声明。

每篇文档的 front matter 记录标题、作者、原文地址、原文更新时间和许可。本地修订记录见 Git 提交历史，`updated_at` 保留原站更新时间。

## 许可与引用

原创文档及社区整理内容采用 [CC BY-SA 4.0](LICENSE.md)。引用的法律、标准和第三方资料保留原出处的许可与权利声明，见各文档和 [NOTICE.md](NOTICE.md)。

引用或改编时，请注明文章标题、作者、原文地址、更新时间及许可，并注明修改。改编内容按相同许可发布。

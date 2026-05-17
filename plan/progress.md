# 写作进度

## 2026-04-29 - 第三章结构图转 PNG

- 状态：待用户确认
- 文件：`chapters/figures/png/fig3_1_pipeline_architecture.png`，`chapters/figures/png/fig3_2_context_graph_schema.png`，`chapters/figures/png/fig3_3_reasoning_workflow.png`
- 内容：使用系统 Quick Look 将第三章 3 张 SVG 结构图渲染为 PNG，并统一改名为标准 `.png` 以便直接插入 Word
- 检查：3 张 PNG 已生成；使用 `sips -g pixelWidth -g pixelHeight` 检查，当前输出尺寸均为 `2400 x 2400`

## 2026-04-29 - 第三章扩写并补系统结构图

- 状态：待用户确认
- 文件：`chapters/03-system-design.md`，`chapters/figures/fig3_1_pipeline_architecture.svg`，`chapters/figures/fig3_2_context_graph_schema.svg`，`chapters/figures/fig3_3_reasoning_workflow.svg`
- 内容：重写第三章，在 `3.1` 到 `3.4` 中补入更完整的设计目标、状态表示、图结构、检索约束和混合裁决说明；新增 3 张系统结构图；将核心算法改写为以 `Input/Output/for/if/return` 为主的符号化伪代码，并补入组装分、束搜索分和最终裁决分的公式描述
- 检查：`wc -m` 统计 `chapters/03-system-design.md` 为 `11822` 字符；`style_check.sh` 通过；3 个 SVG 文件均通过 `xmllint --noout`

## 2026-04-29 - 参考文献扩充到 43 条并统一英文标点

- 状态：待用户确认
- 文件：`chapters/references.md`
- 条目数：43 条
- 内容：保留现有正文已经使用的 `[1]-[19]` 编号顺序，重写全部 19 条原有条目的作者列表与标点格式，去除 `等`、全角标点和中文符号；围绕 LLM Agent 安全、越狱攻击与防御、知识图谱构建、图推理、图增强检索等相关方向追加 `[20]-[43]` 共 24 条文献
- 检查：`awk` 统计条目数为 `43`；`rg` 检索 `等`、`et al` 与全角标点无残留；对 `chapters/references.md` 运行 `style_check.sh`，通过

## 2026-04-27 - 第三章合并系统设计与实现

- 状态：待用户确认
- 文件：`chapters/03-system-design.md`，`chapters/04-implementation.md`，`chapters/05-experiments.md`，`chapters/06-limitations-outlook.md`，`chapters/06-conclusion.md`，`plan/outline.md`，`plan/project-overview.md`
- 内容：按用户要求将原第 3 章系统设计与原第 4 章关键实现合并为“第 3 章 Co-Guard 系统设计与实现”；新版第 3 章保留系统总体架构，并将语义解析与三元组规范化、上下文图谱构建与检索、图推理与安全判定三个模块按“设计目标、架构决策、实现细节”展开；将核心算法伪代码调整为算法 3-1 和算法 3-2；旧 `04-implementation.md` 改为合并说明；实验章章号顺为第 4 章，不足与展望顺为第 5 章
- 检查：对 `chapters/03-system-design.md`、`chapters/05-experiments.md`、`chapters/06-limitations-outlook.md`、`chapters/06-conclusion.md` 运行 `style_check.sh`，均通过；检索 `第五章`、`第六章`、`表 5-`、`图 5-`、`算法 4-` 等残留，当前正文与大纲中未发现

## 2026-04-27 - 第一章补研究目标、第四章补核心算法伪代码

- 状态：待用户确认
- 文件：`chapters/01-introduction.md`，`chapters/04-implementation.md`
- 内容：在 `1.2 研究框架` 中补入研究目标段，明确本文的三个目标是构建可保留跨轮关联的上下文知识图谱、设计面向阶段推进与恶意闭合的图推理机制，以及在三类场景下评估召回能力与误拒边界；在 `4.4 图推理与安全判定实现` 中新增“算法 4-1 上下文组装评分器”和“算法 4-2 Relation-first 多跳搜索”，补入输入、输出、主要步骤、终止条件和复杂度分析
- 检查：对 `chapters/01-introduction.md` 和 `chapters/04-implementation.md` 运行 `style_check.sh`；检索确认 `算法 4-1`、`算法 4-2` 和“研究目标”相关表述已写入目标位置

## 2026-04-27 - 第五章补实验边界、样本量说明与案例分析

- 状态：待用户确认
- 文件：`chapters/05-experiments.md`，`chapters/06-limitations-outlook.md`
- 内容：针对实验方法部分的四项缺口重写第五章相关内容；在 `5.1` 中补入 `advbench_decomposed.jsonl` 的生成来源、拆解脚本路径、子任务统计量以及“未做人类一致性标注”的边界说明；明确解释未直接复现 AutoDefense、UniGuard、Robust Prompt Optimization 的原因；把推理策略对比和基座模型对比的样本量改为固定 `seed=7` 子集的 100 条攻击链，并在表 5-1、表 5-5、表 5-6 中写明；新增 `5.6 典型案例分析`，补入成功拦截、攻击穿透和长期共享上下文误拒三个样例；在“不足与展望”章补入“缺少外部复现基线”和“拆解语料未单独人工标注”的局限
- 检查：对 `chapters/05-experiments.md` 和 `chapters/06-limitations-outlook.md` 运行 `style_check.sh`，均通过；已核对 `data/advbench_decomposed.jsonl` 的条数、字段名和子任务统计量；已核对 `outputs/scenario2_full/20260427-123033/results.json`、`outputs/scenario1_full_current/20260427-000340/results.json`、`outputs/scenario3_full_hybrid/20260426-173910/stream_events.json` 的案例内容；已核对 `outputs/scenario3_rules_seed7/20260426-150320/scenario3_summary.json`、`outputs/scenario3_llm_seed7/20260426-152234/scenario3_summary.json`、`outputs/scenario3_thesis_main_seed7/20260426-141620/scenario3_summary.json`、`outputs/scenario3_llama31_seed7/20260426-183606/scenario3_summary.json` 的样本量均为 100

## 2026-04-27 - 摘要、研究框架与结论改为探索性口径

- 状态：待用户确认
- 文件：`chapters/00-abstract.md`，`chapters/01-introduction.md`，`chapters/03-system-design.md`，`chapters/05-experiments.md`，`chapters/06-conclusion.md`
- 内容：依据场景三良性误拒率 72.97% 的实验结果，降低摘要、研究框架和结论中的定调，将 Co-Guard 表述为多轮拆解攻击检测的探索性原型而非成熟防御方案；同步把 `1.2 研究框架` 改写为“验证可行性并暴露局限”的研究目标；把术语说明和系统设计中“抑制跨链污染”的表述改为“尝试缓解”；把第五章结果讨论中的几处过度积极总结改为“受控实验下的较高召回潜力”和“当前实验中相对更平衡”
- 检查：对 `chapters/00-abstract.md`、`chapters/01-introduction.md`、`chapters/03-system-design.md`、`chapters/05-experiments.md`、`chapters/06-conclusion.md` 运行 `style_check.sh`，均通过；中文摘要正文 389 字符，结论正文 865 字符

## 2026-04-27 - 结论按第五章现结果重写

- 状态：待用户确认
- 文件：`chapters/06-conclusion.md`
- 字数：913 字符
- 内容：删除旧版结论中未被当前第五章结果支撑的 `98.33%`、`2.06` 等主实验均值表述，改为仅引用场景一、场景二、场景三全量对比，以及推理策略对比、基座模型对比中已经出现的结果；同步删除“主实验”“seed”旧叙事
- 检查：对 `chapters/06-conclusion.md` 运行 `style_check.sh`，禁用过渡词、正文列表、无意义加粗和主观化表达检查均通过；检索 `98.33`、`2.06`、`49.94`、`58.65`、`主实验`、`seed`，当前文件中均不存在

## 2026-04-27 - 附录 A/B/C 初稿

- 状态：待用户确认
- 文件：`chapters/appendices-abc.md`，`plan/outline.md`
- 内容：新增附录 A“规范关系与攻击阶段映射表”、附录 B“关键提示词与判定模板”、附录 C“典型检测与误拒案例”；附录 A 依据共享 schema 与阶段映射整理 17 个规范关系及 8 个攻击阶段；附录 B 按实体抽取、三元组抽取、关系定义与规范化、图判定四类模板归纳系统提示词设计；附录 C 选取场景一单 session 拦截、场景二跨 session 拦截和场景三长期共享上下文误拒三个代表性样例
- 检查：已核对 `coguard/semantic/schema.py`、`coguard/reasoning/reasoner.py`、`coguard/semantic/prompts.py`、`coguard/semantic/llm.py` 中的关系词表、阶段映射与提示模板；样例内容已对齐 `outputs/scenario1_full_current/20260427-000340/results.json`、`outputs/scenario2_full/20260427-123033/results.json`、`outputs/scenario3_full_hybrid/20260426-173910/stream_events.json`

## 2026-04-27 - 第 5 章插图按全量实验结果重绘

- 状态：待用户确认
- 文件：`figures/chapter5/plot_experiment_figures.py`，`figures/chapter5/captions.md`，`figures/chapter5/README.md`，`chapters/05-experiments.md`
- 内容：依据更新后的第五章结构和最新实验结果重绘插图；场景图改为 `scenario1_full_current`、`scenario2_full`、`scenario3_full_hybrid` 的全量结果；新增场景误拒/回退与 bypass 构成图、场景三全量事件流稳定性图；删除旧的主实验、版本迭代和主实验 vs 全量实验图的叙事依赖；在第五章正文中补入图 5-1 至图 5-6 的引用位置
- 输出：`fig5_1_scene_comparison`、`fig5_2_scene_detection_curves`、`fig5_3_scene_tradeoff_and_bypass`、`fig5_4_strategy_comparison`、`fig5_5_model_comparison`、`fig5_6_stream_stability` 的 PNG 与 SVG 文件已生成，同时更新 `experiment_digest.json`
- 检查：已使用 `conda run -n base python figures/chapter5/plot_experiment_figures.py` 重新生成插图；人工查看 `fig5_1_scene_comparison.png`、`fig5_3_scene_tradeoff_and_bypass.png`、`fig5_6_stream_stability.png`，确认非空白、中文可读；`chapters/05-experiments.md` 再次通过 `style_check.sh`

## 2026-04-27 - 第 5 章按全量场景结果重写

- 状态：待用户确认
- 文件：`chapters/05-experiments.md`
- 字数：6937 字符
- 内容：依据更新后的 `scenario1_full_current`、`scenario2_full` 和 `scenario3_full_hybrid` 结果重写第五章；实验结构改为三类场景全量对比、推理策略对比和基座模型对比，不再保留旧的主实验多 seed、版本迭代和单独全量实验叙事；补全 `AssemblyDrivenDetectionRate`、`InformationLossBypassRate`、warning/fallback 指标定义，并用场景二 `turn_log.csv` 重新统计良性误拒率和 fallback 率
- 检查：对 `chapters/05-experiments.md` 运行 `style_check.sh`，禁用过渡词、正文列表、无意义加粗和主观化表达检查均通过；已核对 `outputs/scenario1_full_current/20260427-000340/summary.json`、`outputs/scenario2_full/20260427-123033/summary.json`、`outputs/scenario2_full/20260427-123033/turn_log.csv`、`outputs/scenario3_full_hybrid/20260426-173910/scenario3_summary.json`、`outputs/scenario3_rules_seed7/20260426-150320/scenario3_summary.json`、`outputs/scenario3_llm_seed7/20260426-152234/scenario3_summary.json`、`outputs/scenario3_llama31_seed7/20260426-183606/scenario3_summary.json`

## 2026-04-27 - 第 4 章按处理细节再次重写

- 状态：待用户确认
- 文件：`chapters/04-implementation.md`
- 字数：5957 字符
- 内容：按“输入是什么、如何处理、为何这样处理、输出什么”的结构再次重写第四章；弱化函数名和调用链叙述，改为解释单轮流水线、动态意图补全、关系定义与规范化、双层上下文写图、有限跳数检索、相关实体扩展、上下文组装评分、relation-first 多跳搜索、充分性判定以及三类实验执行过程的具体处理细节
- 检查：对 `chapters/04-implementation.md` 运行 `style_check.sh`，禁用过渡词、正文列表、无意义加粗和主观化表达检查均通过；检索 `process_query`、`upsert_query`、`get_context_subgraph`、`assess(`、`SemanticParser`、`Reasoner`、`InMemoryGraphStore`、`CoGuardPipeline` 等实现标识，在章节正文中未发现残留

## 2026-04-26 - 结论重写与新增不足展望章

- 状态：待用户确认
- 文件：`chapters/06-limitations-outlook.md`，`chapters/06-conclusion.md`，`plan/outline.md`
- 字数：`chapters/06-conclusion.md` 当前为 644 字符；`chapters/06-limitations-outlook.md` 当前为 1343 字符
- 内容：重写结论，使其与新版第五章实验叙事保持一致；新增第 6 章“现有不足和未来展望”，单独归纳语义抽取不足、共享长期上下文误拒绝、模型兼容性与评测覆盖范围等边界，并提出后续优化方向；同步在大纲中加入新章节并把术语 `session assembly` 更新为“上下文组装评分器”
- 检查：分别对 `chapters/06-conclusion.md` 和 `chapters/06-limitations-outlook.md` 运行 `style_check.sh`，禁用过渡词、正文列表、无意义加粗和主观化表达检查均通过；结论字数位于学校要求的 400 到 1000 字范围内

## 2026-04-26 - 第 5 章实验部分按执行清单重写

- 状态：待用户确认
- 文件：`chapters/05-experiments.md`，`figures/chapter5/plot_experiment_figures.py`，`figures/chapter5/captions.md`，`figures/chapter5/README.md`
- 字数：`chapters/05-experiments.md` 当前为 9424 字符
- 内容：依据 `论文对比实验执行清单-20260426.md` 和 `论文线程交接-20260426.md` 重写第五章；将结果叙事改为场景对比、主实验三次 seed、版本迭代、推理策略对比、模型对比和全量实验六条比较轴；补充 5 张结果表和 6 张插图对应的图题与绘图脚本；新增 `experiment_digest.json` 作为图表与正文共享的数据摘要
- 检查：对 `chapters/05-experiments.md` 运行 `style_check.sh`，禁用过渡词、正文列表、无意义加粗和主观化表达检查均通过；关键数值已对齐 `scenario1_100`、`scenario2_compare`、`scenario3_thesis_main_seed7/17/27`、`scenario3_thesis_main/v2/v3`、`scenario3_rules_seed7`、`scenario3_llm_seed7`、`scenario3_llama31_seed7`、`scenario3_full_hybrid` 的结果文件；`fig5_1_scene_comparison` 到 `fig5_6_scale_and_bypass` 以及 `experiment_digest.json` 已生成

## 2026-04-26 - 第 4 章关键实现重写

- 状态：待用户确认
- 文件：`chapters/04-implementation.md`
- 字数：7079 字符
- 内容：依据 `writing-chapters`、`writing-core` 和代码实现重写第四章；将原有偏概念说明的写法改为按流水线编排与核心数据结构、三元组抽取与关系规范化、上下文图谱写入与检索、图推理与安全判定、评估执行与场景落地五部分展开；补清 `CoGuardPipeline` 主流程、`QueryAnalysisResult` 结果对象、`SemanticParser` 的 EDC 与 refinement、`BaseGraphStore/InMemoryGraphStore` 的双层上下文实现、`Reasoner` 的 adequacy 与 hybrid 判定边界，以及场景一、场景二、场景三执行器与 checkpoint/resume 实现
- 检查：对 `chapters/04-implementation.md` 运行 `style_check.sh`，禁用过渡词、正文列表、无意义加粗和主观化表达检查均通过；标题层级为 4.1 到 4.5；文件存在且当前字符数为 7079

## 2026-04-26 - 按论文线程交接二次修订

- 状态：待用户确认
- 文件：`chapters/00-abstract.md`，`chapters/01-introduction.md`，`chapters/03-system-design.md`，`chapters/04-implementation.md`，`chapters/05-experiments.md`，`chapters/06-conclusion.md`
- 内容：依据 `论文线程交接-20260426.md` 将论文主结果从旧的 `scenario3 complex v2` 切换为 `scenario3 thesis_main v3` 与三次 seed 均值结果；补入 `scenario2` 场景定义、`hybrid` 为最终策略、规则层只对当前显式恶意保留硬拒、跨轮恶意要求规则与图链路及模型共识、模型对比、全量实验控制变量设计等内容；重写第 5 章实验叙事
- 检查：中文摘要正文 400 字符；结论正文 961 字符；对本轮修改的 6 个章节文件运行 `style_check.sh`，均通过；已人工核对 `scenario2_compare`、`scenario3_thesis_main`、`scenario3_thesis_main_v2`、`scenario3_thesis_main_v3`、`scenario3_thesis_main_seed7`、`scenario3_thesis_main_seed17`、`scenario3_thesis_main_seed27`、`scenario3_rules_seed7`、`scenario3_llm_seed7`、`scenario3_llama31_seed7`、`scenario3_full_hybrid` 的 `summary.json`

## 2026-04-26 - 实验改版后章节重写

- 状态：待用户确认
- 文件：`chapters/00-abstract.md`，`chapters/01-introduction.md`，`chapters/02-related-methods.md`，`chapters/03-system-design.md`，`chapters/04-implementation.md`，`chapters/05-experiments.md`，`chapters/06-conclusion.md`
- 内容：依据 `实验与聊天总结-20260426.md` 重写摘要、第 1 章研究框架与术语说明、第 2 章方法边界说明、第 3 章系统设计、第 4 章关键实现、第 5 章实验章节和结论；将实验叙事从“单链独立 session”调整为“场景一基线 + 场景三长期共享上下文”；补入 `session_id/context_id` 双层上下文、`scenario3 complex v1/v2` 对比、recent-history 与 anchor 对齐修正、checkpoint/resume、模型优先规则兜底等内容
- 检查：中文摘要正文 376 字符；结论正文 860 字符；对上述 7 个文件运行 `style_check.sh`，均通过；已人工核对关键指标与 `scenario1`、`scenario3_fast`、`scenario3_complex`、`scenario3_complex_v2` 的 `summary.json` 一致

## 2026-04-16 - 项目结构

- 状态：已创建
- 内容：创建 `plan/` 和 `chapters/`，记录论文概览与章节大纲
- 用户确认：是

## 2026-04-17 - 摘要

- 状态：待用户确认
- 文件：`chapters/00-abstract.md`
- 中文摘要正文字数：380 字符
- 英文摘要词数：154 词
- 内容：完成中文摘要、中文关键词、英文题目、英文摘要和英文关键词；摘要客观概括研究问题、方法、系统实现、实验结果和结论
- 检查：中文摘要约 300 到 400 字；英文摘要与中文摘要内容对应；未出现“本文”、引用编号、公式和图表；中英文关键词各 5 个；风格检查未发现禁用过渡词、正文列表和无意义加粗

## 2026-04-16 - 第 1 章 绪论

- 状态：待用户确认
- 文件：`chapters/01-introduction.md`
- 字数：6957 字符
- 内容：按用户确认框架完成 1.1 文献综述、1.2 研究框架、1.3 术语说明；1.1 已参考 `thesis/参考文献笔记.rdf` 重写
- 检查：标题层级完整；风格检查未发现禁用过渡词、正文列表和无意义加粗

## 2026-04-16 - 第 2 章 相关理论与方法

- 状态：待用户确认
- 文件：`chapters/02-related-methods.md`
- 字数：5551 字符
- 内容：完成大语言模型安全防御、多轮子任务拆解攻击、知识图谱构建与 EDC、图推理与 Think-on-Graph 思路
- 检查：标题层级完整；风格检查未发现禁用过渡词、正文列表和无意义加粗

## 2026-04-16 - 第 3 章 Co-Guard 系统设计

- 状态：待用户确认
- 文件：`chapters/03-system-design.md`
- 字数：6294 字符
- 内容：完成系统总体架构、语义解析模块、上下文图谱构建模块、图推理与安全判定模块、输入输出与可解释性设计
- 检查：标题层级完整；风格检查未发现禁用过渡词、正文列表和无意义加粗

## 2026-04-16 - 第 4 章 关键实现

- 状态：待用户确认
- 文件：`chapters/04-implementation.md`
- 字数：8050 字符
- 内容：完成数据结构与流水线、EDC 风格抽取与规范化、session 隔离与图存储、relation-first 多跳搜索、顺序注入评估模块
- 检查：标题层级完整；风格检查未发现禁用过渡词、正文列表和无意义加粗

## 2026-04-17 - 第 5 章 实验设计与结果分析

- 状态：待用户确认
- 文件：`chapters/05-experiments.md`
- 字数：6662 字符
- 内容：完成实验数据与环境、顺序注入流程与评价指标、100 条和 520 条样本结果、bypass 分类与失败原因分析、结果讨论
- 检查：标题层级完整；风格检查未发现禁用过渡词、正文列表和无意义加粗

## 2026-04-17 - 结论

- 状态：待用户确认
- 文件：`chapters/06-conclusion.md`
- 字数：1000 字符
- 内容：按学校要求改为不加章号的“结论”章，归纳主要成果、突出创新点，并简要说明实验结果与后续不足
- 检查：标题不带章号；字数位于 400 到 1000 字范围；风格检查未发现禁用过渡词、正文列表和无意义加粗

## 2026-04-17 - 参考文献

- 状态：待用户确认
- 文件：`chapters/references.md`
- 条目数：19 条
- 内容：按正文首次出现顺序整理 19 条参考文献，改为学校模板可直接复制到 Word 尾注的著录格式；已在第 1 至第 5 章对应位置插入引用编号；修正 Robust Prompt Optimization 作者顺序为 Li、Wang 和 Zhou
- 检查：条目均包含出版信息、页码或可访问来源；正文引用编号与参考文献编号一一对应；风格检查未发现禁用过渡词、正文列表和无意义加粗

## 2026-04-24 - 第 5 章实验插图

- 状态：待用户确认
- 文件：`figures/chapter5/fig5_1_core_metrics_comparison.png/.svg`，`figures/chapter5/fig5_2_cumulative_detection_curve.png/.svg`，`figures/chapter5/fig5_3_bypass_breakdown.png/.svg`
- 内容：基于 `outputs/scenario1_100/20260410-120457/scenario1_metrics.json` 和 `outputs/scenario1/20260410-151254/scenario1_metrics.json` 生成论文插图，覆盖核心指标对比、前 10 轮累计检测曲线和 bypass 类型构成；补充 `figures/chapter5/captions.md` 作为图题建议
- 检查：输出 PNG 和 SVG 两种格式；PNG 分辨率约为 450 DPI；已人工复核中文字体、图例、柱状标注和布局无遮挡

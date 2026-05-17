# 模块三：推理与风险判定模块

## 1. 模块目标

推理模块负责根据：

- 当前查询
- 当前查询抽取出的标准化三元组
- 图模块返回的上下文子图

判断这次请求是应该：

- `allow`
- 还是 `refuse`

当前实现已经不是最初的“关键词加总器”，而是一个受 Think-on-Graph 启发的 `relation-first` 路径推理器。它的目标不是回答知识问答，而是沿图中的关系路径收集风险证据与反证，再判断证据是否已经足够支持最终决策。

当前还支持三种推理策略：

- `rules`
  只使用 relation-first 规则推理。
- `llm`
  让 LLM 基于图证据做最终判决，但仍复用规则推理产出的证据路径。
- `hybrid`
  先跑规则推理，再用 LLM 做二次审阅，最后按保守策略融合两者结论。

默认推荐 `hybrid`，因为它最符合“模型优先、规则兜底”的系统目标：

- 规则层负责稳定产出路径证据
- LLM 负责做更强的语义判别
- 模型不可用时仍然可以完整退回规则推理

## 2. 文件结构

- `reasoner.py`
  模块主体，包含路径搜索、路径打分、充分性判断与最终决策逻辑。
- `__init__.py`
  导出 `Reasoner`。

## 3. 设计思路

### 3.1 从“信号累计”升级到“路径证据”

安全判定里一个常见问题是：

- 只靠关键词容易误伤
- 只看当前一句话容易漏掉多跳意图

例如：

- “分析用户反馈并更新知识库”
  看起来有 `更新`，但本质是良性任务
- “攻击者使用多个Agent绕过安全策略并窃取API密钥”
  真正危险的不只是单个词，而是整条关系链

所以模块三采用的是：

1. 先构造路径搜索空间
2. 再搜索和裁剪候选路径
3. 最后判断当前证据是否足够

如果启用了 `hybrid` 或 `llm`，规则推理不会被移除，而是继续承担：

- 图遍历
- 证据路径生成
- 反证路径生成
- 缺失链路识别

LLM 负责补一层“图证据审阅”，尤其适合处理规则边界附近的复杂样本。

## 4. 输入信号构建

`assess()` 开始后，首先会构造 `_QuerySignals`。

它会从：

- 原始 query
- `context_description`
- 当前 triples 的 `raw_relation`
- 当前 triples 的 `normalized_relation`
- 当前 triples 的 object

拼成一个组合文本，再提取以下信号：

- 风险关键词得分
- 良性关键词得分
- 是否涉及多智能体
- 是否涉及秘密资产
- 是否涉及策略 / guardrail
- 是否涉及 payload
- 是否更像分析型请求
- 当前 query 里出现的关系集合
- 当前 query 里出现的实体集合

这些信号会在后面反复参与：

- 路径打分
- 充分性判断
- 最终决策

## 5. 路径搜索空间构建

### 5.1 图预处理

推理模块接收的是 `ContextSubgraph`。

它会先把子图转成：

- `node_map`
- `adjacency`

并且忽略 `mentions` 边，只保留实体之间的语义关系边。

### 5.2 初始种子

初始路径不是从全图所有实体出发，而是从与当前 query 最相关的实体出发：

- 当前 triples 的 subject
- 当前 triples 的 object
- 当前 query 的 `mentions` 到的实体

每个种子实体会构造成 `_PathState`，包含：

- 当前 frontier
- 已走过的 steps
- risk score
- benign score
- overall score
- 已访问实体
- 已访问边

因此，推理器不是一次性看完整张图，而是围绕当前 query 的种子逐步展开。

## 6. Relation-first 搜索

这部分是当前推理模块最核心的设计。

### 6.1 为什么 relation-first

安全判定中，关系语义往往比中间实体更稳定。

例如：

- `bypasses_guardrail`
- `exfiltrates_secret`
- `executes_payload`

这些关系本身就带有较强风险含义。

因此当前实现不是纯实体搜索，而是先做“关系扩展”，再做“实体扩展”。

### 6.2 Relation Search

对每条活跃路径，遍历当前 frontier 的相邻边，构造 `_Traversal`。

每个 traversal 记录：

- source / target
- relation
- direction
- query_id
- next entity
- edge key

随后按：

- 现有路径签名
- relation
- direction

聚合成 `_RelationCandidate`。

### 6.3 Relation Prune

每个 `_RelationCandidate` 会被 `_score_relation_candidate()` 打分。

得分来源包括：

- `RELATION_BRIDGE`
  关系本身是否适合作为推理桥梁
- `RELATION_RISK`
  关系自身风险强度
- `RELATION_BENIGN`
  关系自身良性强度
- 是否与当前 query 的关系一致
- 是否与当前信号一致
  例如 query 中提到 guardrail，则 `bypasses_guardrail` 会被额外提升
- 候选下一跳实体的风险或良性特征

排序后只保留 top-N 的高分关系候选。

### 6.4 Entity Search

在选出的关系候选之下，遍历对应 traversal，把具体实体扩进去，生成新的 `_PathState`。

这里会更新：

- 新 step
- 新 frontier
- 新的 risk / benign score
- 访问过的节点和边

然后再基于 beam width 做一次路径裁剪。

## 7. 路径打分机制

路径不是用单一分数表示，而是三套分数同时维护：

- `risk_score`
- `benign_score`
- `overall_score`

### 7.1 风险得分来源

主要来自：

- 高风险关系先验
  例如 `bypasses_guardrail`、`exfiltrates_secret`
- 风险实体
  例如密钥、凭证、payload、权限、策略对象
- 风险链 bonus
  例如：
  - `uses_tool -> bypasses_guardrail`
  - `bypasses_guardrail -> exfiltrates_secret`
  - `executes_payload -> escalates_privilege`
- 当前 query 信号增强
  例如提到多智能体、guardrail、secret、payload

### 7.2 良性得分来源

主要来自：

- 良性关系先验
  例如 `requests_information`、`analyzes_target`
- 良性实体
  例如反馈、报表、知识库、文档
- 良性链 bonus
  例如：
  - `requests_information -> analyzes_target`
  - `analyzes_target -> updates_resource`

### 7.3 综合得分

`overall_score` 大致可理解为：

- 风险证据
- 减去良性证据
- 再加上与当前 query 的相关性修正

这使得系统不会因为单一风险词就立刻高危，也不会因为出现“分析”二字就完全放松警惕。

## 8. 充分性判断

这是受 ToG 启发最明显的一步。

模块不会在第一轮就直接给最终结论，而是每轮扩展后调用 `_judge_adequacy()` 判断：

- 当前路径证据是否已经足够支持 `refuse`
- 是否已经足够支持 `allow`
- 还是还需要继续扩展

当前 adequacy 状态有三种主要取值：

- `sufficient_for_refuse`
- `sufficient_for_allow`
- `uncertain`

如果仍然证据不足，就在 `reasoning_max_depth` 范围内继续扩展。

## 9. 最终决策

当路径搜索结束后，模块会输出：

- `evidence_paths`
  风险证据路径
- `counter_evidence_paths`
  良性反证路径
- `missing_links`
  当前缺失的关键链路
- `score`
  最终风险分
- `reasons`
  可读解释

### 9.1 风险路径

风险路径会优先保留：

- 风险分高
- 链条清晰
- 与当前 query 强相关

的路径。

### 9.2 反证路径

良性路径会优先保留：

- 分析型
- 说明型
- 文档 / 报表 / 知识库更新型

的路径。

### 9.3 缺失链路

如果证据还不够，系统会显式指出缺什么，例如：

- 没有看到多代理协作到下游危险动作的连接
- 没有看到 guardrail 绕过链
- 没有看到秘密抽取链
- 没有看到分析型路径

这对后续调试和误判分析很有帮助。

## 10. 输出数据结构

推理模块相关输出定义在 `coguard/models.py`：

- `ReasoningStep`
- `ReasoningPath`
- `QueryAnalysisResult` 中的：
  - `reasoning_mode`
  - `adequacy`
  - `evidence_paths`
  - `counter_evidence_paths`
  - `missing_links`

这意味着推理层不再只输出一个 `True / False`，而是能输出“为什么”。

## 11. 配置项

模块三受以下配置控制：

- `REASONING_MAX_DEPTH`
- `REASONING_BEAM_WIDTH`
- `REASONING_RISK_EVIDENCE_THRESHOLD`
- `REASONING_BENIGN_EVIDENCE_THRESHOLD`

它们分别控制：

- 最多扩展多少轮
- 每轮保留多少条路径
- 何时认为风险证据足够
- 何时认为良性证据足够

## 12. 当前限制

当前实现仍然是“规则打分 + 路径搜索”的离线版，而不是完整 LLM pruning。

限制主要有：

1. 路径打分依赖手工设定的关系先验和链 bonus。
2. 充分性判断仍然是规则式，而不是让模型做更细的 judge。
3. 路径搜索只在当前局部子图上进行，不会主动再去外部检索。
4. Neo4j 与内存后端都能提供上下文，但上下文质量仍然受图构建质量影响。

## 13. 总结

模块三可以理解为一个“图增强的安全判定器”。

它不再只是检测危险词，而是试图回答三个更关键的问题：

1. 当前 query 在图里形成了哪些关系链。
2. 这些关系链更像风险执行链，还是良性分析链。
3. 现有证据是否已经足够支撑决策。

这让系统在面对：

- 多跳风险意图
- 多代理协作
- 历史上下文累积

这些场景时，比单纯规则分类器更稳，也更容易解释和调试。

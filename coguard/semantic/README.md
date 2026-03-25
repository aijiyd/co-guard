# 模块一：语义解析模块

## 1. 模块目标

语义解析模块负责把原始自然语言查询转换成系统内部可消费的结构化三元组。它采用的是一条贴近 EDC 框架的流水线：

1. `Extract`
   从原始文本中抽取开放式三元组。
2. `Define`
   为每种关系生成自然语言定义。
3. `Canonicalize`
   将开放关系映射到系统统一的风险关系 schema。
4. `Refinement`
   利用候选实体和候选关系提示，对抽取结果再跑一轮修正。

这个模块的核心目标不是做最强的通用信息抽取，而是为后续图构建和风险推理提供稳定、可解释、可迭代的结构化输入。

## 2. 目录结构

- `parser.py`
  语义解析主入口，负责串起抽取、定义、标准化和聚类。
- `llm.py`
  LLM 适配层，定义统一接口，并提供规则版与本地 OpenAI-compatible 版实现。
- `prompts.py`
  few-shot prompt 模板，覆盖实体抽取、OIE、关系定义和 canonicalization。
- `schema.py`
  标准关系 schema 与同义词表。
- `vectorizer.py`
  轻量向量化与相似度计算。
- `retriever.py`
  schema retriever，给 refinement 阶段提供候选关系。
- `__init__.py`
  模块导出入口。

## 3. 核心流程

### 3.1 Extract：开放式三元组抽取

入口是 `SemanticParser.parse()`。它首先调用 `llm_adapter.extract_triples()`，得到一组三元组：

- `subject`
- `relation`
- `object`

这里的 `relation` 允许是开放关系，不要求一开始就落在系统预定义 schema 上。

当前有两种实现：

1. 规则版 `RuleBasedLLMAdapter`
   作为离线 fallback，可在没有真实模型服务时跑通整条链路。
2. `OpenAICompatibleLLMAdapter`
   面向本地部署模型，走 `/v1/chat/completions` 接口，并使用 few-shot prompt 返回 JSON。

规则版抽取逻辑的关键点：

- 先按句号、分号、换行等切分片段。
- 基于 schema 同义词和开放关系提示词构造正则。
- 用关系词在句中位置切出 `subject / relation / object`。
- 支持跨句主语承接。
  例如第二句以 `He`、`他`、`该系统` 开头时，会继承上一个显式主语。
- 支持链式主语传递。
  如果关系属于 `use / delegate / coordinate / 使用 / 委派 / 协调` 这一类链式动作，后一跳会以上一跳的 object 为新 subject。
- 抽不到时回退为 `user -> ask -> 原始问题`。

这种实现保证了：

- 没有模型时可以离线运行。
- 接入模型后不需要改上层接口。

### 3.2 Define：关系定义生成

抽到三元组后，`parse()` 会调用 `llm_adapter.define_relations()`，为每个不同关系生成定义文本。

定义阶段的作用很重要，因为后续 canonicalization 不是只看关系名，而是看“当前语境下这个关系到底表达了什么语义”。

例如：

- `selectedByNasa`
  会被定义为“主体在某年被 NASA 选中”
- `uses_tool`
  会被定义为“主体使用工具或能力完成任务”

规则版定义器的来源有三层：

1. schema 精确命中
   如果关系本身已经命中标准 schema，就直接采用 schema definition。
2. 规则模板
   对常见关系如 `born on`、`member of`、`selected by` 使用手工定义模板。
3. 基于 object 类型的兜底模板
   例如把 object 判断成时间、秘密、地点、组织等，再生成“subject 对某类对象执行关系”的定义。

### 3.3 Canonicalize：关系标准化

这是 `parser.py` 里的关键步骤。

系统会把关系定义向量化，然后和标准 schema definition 做相似度匹配：

1. 把当前 relation definition 转成稀疏向量。
2. 对所有 schema definition 计算余弦相似度。
3. 取 `top_k` 候选。
4. 如果 raw relation 命中同义词表，则把对应 schema 候选强行提升到前面。
5. 再调用 `choose_canonical_relation()` 做最后验证。

如果验证通过，就映射到标准 schema。

如果验证不通过，就保留为 `custom_*` 关系。

这一步的设计思路是：

- 先“检索候选”
- 再“做语义确认”
- 最后才“决定是否归一化”

这样可以避免把开放关系过早错误压缩进固定 schema。

### 3.4 Refinement：候选提示回灌

模块本身支持 refinement，但真正调度是在 `pipeline.py` 里完成。

第二轮解析时，模块会接收：

- `candidate_entities`
- `candidate_relations`

这些提示来自：

- 第一轮抽取出的实体
- 单独的实体抽取结果
- schema retriever 检出的高相关关系

在 few-shot OIE prompt 里，这些内容会以“候选实体 / 候选关系”形式附带给模型，帮助它在第二轮更容易抽出缺失关系。

## 4. 轻量向量化设计

`vectorizer.py` 没有引入重量级 embedding 模型，而是做了一个原型级文本向量器：

- 英文按 `[a-z0-9_]` token 切分
- 中文按单字和双字 bigram 编码
- 用归一化词频构造稀疏向量
- 用余弦相似度比较文本

这个设计的目的不是替代真正 embedding，而是：

- 让系统在无外部模型时也能工作
- 给 schema 匹配和关系聚类提供一个成本很低的相似度基础

## 5. Schema Retriever 设计

`retriever.py` 负责在 refinement 前检索和当前 query 最相关的 schema relation。

当前支持三种后端：

1. `vector`
   使用本地稀疏向量相似度。
2. `sentence_transformer`
   使用 sentence-transformers 编码 query 和 schema。
3. `openai_embedding`
   使用本地 OpenAI-compatible embedding 服务。

其中：

- `sentence_transformer`
- `openai_embedding`

如果加载失败或服务失败，会自动回退到 `vector` 检索，并把原因写入 warning。

## 6. Few-shot Prompt 设计

`prompts.py` 中维护了四类模板：

1. 实体抽取
2. OIE 抽取
3. 关系定义
4. canonicalization 选择

这些 prompt 的共同设计原则是：

- 输出必须是 JSON
- few-shot 示例覆盖英文与中文场景
- 允许使用候选提示，但不强制模型只从候选中选

这让本地模型即使能力一般，也更容易按稳定格式返回结果。

## 7. 数据边界

这个模块输入输出的数据协议在 `coguard/models.py` 中定义：

- 输入阶段主要使用 `RawTriple`
- 输出阶段主要使用 `NormalizedTriple`
- 候选关系使用 `RelationCandidate`
- schema 本体使用 `SchemaRelation`

模块一的职责到这里为止：

- 它负责把语言变成结构化关系
- 但不负责存图
- 也不负责风险判定

## 8. 可扩展点

后续如果要继续增强，优先级建议如下：

1. 替换更强的本地 LLM 作为 `extract / define / choose_canonical_relation` 后端。
2. 增加更贴论文的示例库，针对你自己的安全场景做 few-shot 专门化。
3. 给 entity normalization 增加别名和共指处理。
4. 把 relation definition 与 canonicalization 做成可缓存流程，减少重复请求。

## 9. 总结

模块一本质上是“EDC 风格的开放信息抽取与语义标准化器”。

它的关键价值不在于某一步单点最强，而在于把：

- 开放关系抽取
- 关系定义
- schema 对齐
- refinement

整合成一条统一、可回退、可解释的语义解析链，为图模块和推理模块提供稳定输入。

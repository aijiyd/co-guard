# 模块二：图构建与上下文存储模块

## 1. 模块目标

图模块负责把语义解析模块输出的标准化三元组增量写入图中，并围绕“当前 query”抽取局部上下文子图，提供给推理层使用。

这个模块解决两个核心问题：

1. 如何把每次查询都记录成可追踪的图结构。
2. 如何从历史查询中取回对当前判断最有用的上下文证据。

## 2. 目录结构

- `store.py`
  图存储抽象与两个后端实现。
- `entity_similarity.py`
  实体相关性建模，用于上下文扩展。
- `__init__.py`
  导出图模块公共接口。

## 3. 图数据模型

图中的元素分为三类：

1. Query 节点
   表示一次用户查询。
2. Entity 节点
   表示三元组中的 subject / object。
3. Edge
   分为两种：
   - `mentions`
     表示当前 query 提到了某个实体。
   - 语义关系边
     表示 subject 与 object 之间存在某种标准化关系。

因此，一次查询写入图后会形成：

- 一个 `Query`
- 若干 `Entity`
- `Query -> Entity` 的 `mentions`
- `Entity -> Entity` 的标准关系边

关系边会保留语义解析模块传下来的重要属性：

- `query_id`
- `raw_relation`
- `confidence`
- `cluster_id`

这保证后续推理时不仅能看到“谁和谁有关”，还能看到“这条关系来自哪次 query、原始关系词是什么、置信度如何”。

## 4. 抽象接口设计

`BaseGraphStore` 定义了统一接口：

- `upsert_query(query, triples)`
- `get_context_subgraph(query_id, hops, limit)`

这样上层 `pipeline.py` 不需要关心底层是：

- 内存图
- 还是 Neo4j

只要接口一致，后端就可以自由切换。

## 5. InMemoryGraphStore 设计

默认后端是 `InMemoryGraphStore`。

它内部使用三个主要结构：

- `_nodes`
  `node_id -> GraphNode`
- `_edges`
  图中的边列表
- `_adjacency`
  `node_id -> 相邻边索引集合`

### 5.1 写入流程

每次调用 `upsert_query()` 时会：

1. 新建一个 `query-xxxx` 节点。
2. 为每个三元组的 subject / object 生成 entity id。
3. 创建或复用实体节点。
4. 记录实体类型 `entity_type`。
5. 建立 `mentions` 边。
6. 建立标准关系边。

实体节点 id 使用实体名的 SHA1 前缀生成，因此：

- 完全同名实体会落在同一个节点上
- 不同名字不会自动融合

### 5.2 上下文提取流程

`get_context_subgraph()` 并不是直接返回全图，而是围绕当前 `query_id` 抽局部图。

步骤如下：

1. 从 query 节点开始 BFS。
2. 在 `hops` 范围内扩展。
3. 用 `limit` 控制节点数。
4. 再调用 `_expand_with_related_entities()` 做相似实体扩展。

这样做的优点是：

- 推理层看到的是局部证据，而不是噪声很大的全图
- 复杂度可控
- 查询历史可以累积，但不会无限扩散

## 6. 相似实体扩展设计

这是图模块里比较关键的增强能力。

### 6.1 为什么要做

如果当前 query 提到的是 `订单数据`，而历史里存的是 `客户订单数据`，两者完全不同名，但语义上显然有关。

如果只靠完全同名匹配，很多历史上下文会丢失。

### 6.2 EntityProfile

`entity_similarity.py` 会把实体名编码成 `EntityProfile`，包含：

- `normalized`
- `compact`
- `core_normalized`
- `core_compact`
- `tokens`
- `vector`
- `entity_type`

这里做了几层归一化：

- 小写化
- 去前导冠词
- 去噪声字符
- 去空格
- 去通用后缀
  例如 `system / service / dataset / 数据库 / 报表 / 文档`

### 6.3 相似度计算

`entity_relatedness_score()` 采用的是中等复杂度方案，综合三部分：

1. lexical overlap
   token 集合重叠度。
2. vector similarity
   基于轻量稀疏向量的余弦相似度。
3. type compatibility
   基于实体类型的兼容性约束。

权重为：

- `0.45 * token_overlap`
- `0.35 * vector_similarity`
- `0.20 * type_score`

另外还有几条早停规则：

- 完全相同直接返回 `1.0`
- 核心名称互相包含时给高分
- 类型不兼容直接判 `0`
- token overlap 和 vector similarity 都太低时直接判 `0`

### 6.4 类型约束

实体会被粗分到以下类型：

- `time`
- `location`
- `org`
- `tool`
- `data`
- `group`
- `generic`

这个类型约束非常重要，因为它能避免类似：

- `订单数据`
- `订单工具`

仅因字面重叠而被错误拉进同一上下文。

### 6.5 扩展策略

当某个候选实体相关性分数超过阈值时，模块不会只把“这个实体节点”加进上下文，而是会把：

- 相关实体本身
- 它的一跳边
- 它的一跳邻居节点

一起补进当前 `ContextSubgraph`。

原因是推理层真正需要的不是“相似实体名单”，而是“围绕这个相似实体的关系证据”。

## 7. Neo4jGraphStore 设计

`Neo4jGraphStore` 的目标是和内存后端保持同语义、不同实现。

### 7.1 写入

写入时会：

- `MERGE` Query 节点
- `MERGE` Entity 节点
- 写入 `MENTIONS`
- 写入 `RELATION`

同时存储：

- `normalized_relation`
- `raw_relation`
- `confidence`
- `cluster_id`
- `entity_type`

### 7.2 查询

读取上下文时，会从当前 query 出发构造多跳 Cypher 查询：

- 先收集 query 与多跳邻域内的节点
- 再把这些节点之间的边一起收回
- 最后转换成统一的 `ContextSubgraph`

当前需要注意的是：

- Neo4j 后端目前主要支持标准 BFS 子图查询
- 内存版的“相似实体扩展”逻辑还没有完整移植到 Neo4j 查询层

所以在功能上，内存版的上下文扩展会更激进一些。

## 8. 数据边界与上游下游关系

这个模块的输入来自语义模块：

- `NormalizedTriple`

输出给推理模块的是：

- `ContextSubgraph`

因此它承担的是一个很清晰的中间层职责：

- 向上承接结构化语义
- 向下提供局部图证据

## 9. 配置项

图模块相关配置主要在 `.env` 与 `AppConfig` 中：

- `GRAPH_BACKEND`
- `ENTITY_RELATEDNESS_THRESHOLD`
- `CONTEXT_HOPS`
- `CONTEXT_LIMIT`
- `NEO4J_URI`
- `NEO4J_USERNAME`
- `NEO4J_PASSWORD`
- `NEO4J_DATABASE`

这些参数分别控制：

- 后端类型
- 相似实体扩展阈值
- 上下文搜索深度
- 子图规模上限
- Neo4j 连接信息

## 10. 总结

模块二本质上是一个“带上下文检索能力的证据图存储层”。

它的设计重点不是做一个通用知识图谱平台，而是围绕当前安全判定任务，提供三种能力：

1. 每次 query 的增量落图
2. 历史上下文的可追踪保留
3. 对当前 query 最相关的局部图证据抽取

这使得推理层可以不再只看当前一句话，而是结合历史关系和相似实体周边证据做判断。

# 3 Co-Guard 系统设计与实现

## 3.1 系统总体架构

Co-Guard 是一个部署在用户输入与目标大语言模型之间的外部安全护栏系统，其设计对象是多轮子任务拆解攻击[7,8,10]。这类攻击的关键不在于单轮输入足够危险，而在于多条表面中性的查询在历史上下文中逐步形成目标识别、弱点发现、能力获取、执行准备和规避管理等阶段链。系统因此不直接把当前输入视为独立样本，而是把“当前输入写入历史之后形成的结构化状态”作为判断对象。

从运行边界看，Co-Guard 不修改被保护模型的参数，也不要求目标模型暴露内部表示。它只接收当前查询 `q_i` 及其上下文标识，完成语义解析、图谱写入、局部检索和图推理，再输出允许或拒绝决策。该边界与单轮提示防御不同，后者主要依赖当前输入的词面特征或固定后缀；Co-Guard 的判断依赖可追溯的跨轮结构证据，因此更接近在线状态机和图约束判定的结合体。其总体流程如图 3-1 所示。

![](figures/fig3_1_pipeline_architecture.svg)

图 3-1 Co-Guard 在线防御流水线

系统主流水线可以写为

$$
q_i \xrightarrow{\text{parse}} T_i \xrightarrow{\text{write}} G_i \xrightarrow{\text{retrieve}} C_i \xrightarrow{\text{reason}} A_i \xrightarrow{\text{decide}} y_i
$$

其中 `q_i` 表示第 `i` 轮用户查询，`T_i` 表示本轮经语义解析后得到的规范化三元组集合，`G_i` 表示写入本轮后形成的上下文图，`C_i` 表示围绕当前查询检索得到的局部子图，`A_i` 表示推理模块输出的风险摘要，`y_i in {allow, refuse}` 表示最终裁决。若第 `i` 轮被拒绝，后续查询不再继续进入目标模型，从而形成早停式防御。

整体架构被拆成三个顺序耦合的模块。第一模块负责把自然语言压缩为可计算的关系表示，解决“当前轮到底表达了什么动作”的问题。第二模块负责把本轮关系写入具有时间和来源信息的上下文图，并按边界约束检索局部证据，解决“哪些历史与当前轮真正相关”的问题。第三模块负责将当前轮信号、历史阶段链、局部路径和反证路径合并起来裁决，解决“当前轮是否与历史共同闭合恶意链”的问题。这样划分后，系统既能在线处理单轮请求，也能把长期共享上下文下的历史累积保持在有限可控的检索范围内。

Co-Guard 采用 `session_id` 与 `context_id` 双层上下文边界。`session_id` 表示外层对话或请求批次，主要用于样本隔离、日志定位和清理；`context_id` 表示运行时可见的长期共享上下文。当输入未显式给出 `context_id` 时，系统以 `session_id` 作为有效上下文；当多个 `session_id` 共享同一 `context_id` 时，系统允许这些外层会话向同一图上下文持续写入。这一设计直接服务于三个实验场景：场景一是单 `session` 独立累积，场景二是跨 `session` 但共享同一上下文，场景三则在单一长期上下文中交织多条隐藏链。

从状态表示看，系统不保存攻击者真实目标编号，也不保存评测器离线维护的隐藏标签。运行时可见状态只包括当前轮文本、该轮抽取出的实体与关系、历史查询节点、局部证据路径以及少量派生摘要，如共享主题、共享锚点、阶段推进标记和风险分数。这种状态约束有两个目的。其一是尽量贴近实际部署环境，避免依赖实验环境中才存在的理想标签。其二是把安全判定收敛到可解释的结构证据上，使每次拒绝都能回溯到明确的路径或阶段闭合，而不是来自无法解释的内部阈值。

在执行策略上，系统遵循“模型优先，规则兜底”的原则。语义抽取、关系规范化和图级裁决优先由模型完成，因为多轮拆解攻击的关键关系往往是隐式、压缩和跨句的，单纯规则无法稳定恢复。规则层保留两类职责：一是当前查询本身已经足够恶意时的硬拒，二是模型超时、格式异常或服务不可用时的最小可用回退。跨轮组装式恶意不由规则单独下结论，而要求图证据和模型判断共同支持拒绝。这一边界并不意味着误拒已被消除，相反，第 4 章实验表明长期共享上下文下误拒仍然偏高，因此本系统更适合作为探索性原型而非直接部署方案。

## 3.2 语义解析与三元组规范化

语义解析模块的设计目标，是把自然语言查询压缩为后续图模块可直接操作的结构化表示，同时尽量保留拆解攻击中的阶段信息与动作实质。若这一阶段只输出泛化的“用户询问某事”，则后续图谱虽然可以保存历史，却无法识别“目标识别”与“执行准备”的差异；若这一阶段过早把不同表达全部压平，则“绕过护栏”“获取凭证”“调用工具”和“读取数据”之间的阶段边界又会丢失。因此，该模块的首要任务不是追求简洁，而是在结构化与信息保真之间取得平衡。

Co-Guard 延续 EDC 的 Extract、Define、Canonicalize 三阶段思想[14]，但把它改造为面向在线防御的解析流水线。给定一条查询 `q_i`，系统先抽取开放式三元组

$$
T_i^{(0)} = \{(s_k, \hat{r}_k, o_k)\}_{k=1}^{n_i}
$$

其中 `s_k`、`\hat{r}_k` 和 `o_k` 分别表示主语、原始关系和宾语。这里的 `\hat{r}_k` 不要求来自预定义 schema，因为多轮拆解攻击里的动作表达高度开放，固定标签很难一次性覆盖。“准备下一步材料”“降低暴露风险”“确认入口条件”这类表达若被强行塞进有限关系表，往往会在抽取阶段就损失语义。

开放式抽取之后，系统为每条原始关系生成一段关系定义 `d(\hat{r}_k)`，再与内部 schema 中每个规范关系 `r in R` 的定义 `d(r)` 做语义匹配。其核心映射可以写为

$$
r_k^\ast = \arg\max_{r \in R} \; \mathrm{sim}\bigl(\phi(d(\hat{r}_k)), \phi(d(r))\bigr)
$$

其中 `\phi(.)` 表示文本表示函数，`sim(.)` 表示相似度函数。若最高相似度低于阈值 `\tau_c`，则该关系不被强制映射到高风险标签，而保留为 `custom_*` 关系。这样做的原因在于，开放域查询中经常出现研究型、分析型或纯流程型动作，它们与高风险关系存在词面重叠，但并不一定应被解释为攻击推进。

系统内部的规范关系集合覆盖 `identifies_target`、`discovers_weakness`、`acquires_capability`、`plans_execution`、`plans_evasion`、`bypasses_guardrail`、`retrieves_data`、`exfiltrates_secret`、`executes_payload` 和 `escalates_privilege` 等高风险动作，也保留 `requests_information`、`analyzes_target`、`stores_data`、`updates_resource` 和 `communicates_with` 等较中性的关系。高风险关系与良性关系同时存在的目的，不是把所有查询二元划分为“恶意”或“良性”，而是让图推理阶段能够同时积累证据路径和反证路径，避免系统只会单向放大风险。

多轮拆解攻击中的一个难点，是许多查询并不直接陈述动作，而是以短句、省略句或规划性问法出现，例如“还需要什么条件”“下一步该准备哪些东西”“怎样不被发现”。这类输入在词面上可能只包含提问结构，不包含明确谓词。为此，系统在开放式抽取后增加动态意图补全机制。若当前轮只得到空结果，或仅得到过于宽泛的弱语义三元组，系统会检测查询中是否出现阶段推进线索、目标延续线索和规避型表述，再从原句中裁出真正的任务焦点，补形成如 `(user, plans_execution, payload)` 或 `(user, plans_evasion, detection)` 这类意图三元组。补全过程并不依赖固定模板，而是要求补出的关系能够与当前句面和历史阶段一致，否则宁可保留弱关系，也不把模糊表达硬解释成高风险动作。

为降低同一轮内近义表达反复计数的问题，系统在规范化后对当前轮关系做局部合并。设第 `i` 轮规范化后的关系集合为 `R_i = {r_1^\ast, ..., r_m^\ast}`，若两条关系定义的相似度高于 `\tau_m` 且其主宾语组合一致，则系统把它们归入同一簇 `g_j`，在后续图写入时共享局部簇标识。这样做的目的不是删除重复信息，而是使推理模块能够区分“同一动作被不同表述重复强调”和“确有多个不同动作并行存在”。

仅做一轮抽取仍可能遗漏长句中的次级动作，或把局部查询解释得过窄。系统因此加入一轮轻量细化。第一轮得到的实体、关系定义与候选规范关系会作为上下文提示回送给解析器，要求第二轮在这些提示下补足缺失实体、关系方向和动作目标。若第二轮结果与第一轮完全一致，细化立即终止；若出现新增关系但全部为低置信度，系统只保留与已有高置信度关系一致的补充项。终止条件写为

$$
T_i^{(t+1)} = T_i^{(t)} \quad \text{or} \quad t = t_{\max}
$$

其中 `t_max` 在当前实现中取 2。这样既能利用一次自校正提升抽取稳定性，又避免在线流水线陷入高成本迭代。

语义解析模块的输出不是单一三元组列表，而是一个带属性的关系包。每条关系同时保留原始关系、关系定义、规范关系、候选集合、置信度和局部簇标识。后续图模块正是利用这些附加属性区分“当前轮直接表达的关系”“由定义映射得到的关系”和“仍存在歧义的关系”。这种设计使得后续误拒分析不必回到原始模型日志即可重建一轮解析是如何发生的。

## 3.3 上下文图谱构建与检索

上下文图谱模块的设计目标，是把逐轮解析结果转化为可累积、可检索、可追溯的图结构。对于多轮拆解攻击，仅保存线性聊天历史是不够的，因为线性文本只能说明顺序，无法显式表达“哪一轮提到过同一对象”“哪些动作共享目标实体”“哪条历史关系与当前轮形成阶段桥接”。图结构之所以必要，正在于它允许系统围绕当前轮只取相关局部，而不是每次把全部历史重新交给模型阅读。

系统将有效上下文 `c` 下的知识图表示为

$$
G_c = (V_q, V_e, E_m, E_r, \mathcal{A})
$$

其中 `V_q` 表示查询节点集合，`V_e` 表示实体节点集合，`E_m` 表示查询到实体的 `mentions` 边集合，`E_r` 表示实体间的语义关系边集合，`\mathcal{A}` 表示节点和边的属性集合。`query` 节点保存原始文本、时间戳、`session_id` 和 `context_id`；`entity` 节点保存实体名称、归一化名称和实体画像；语义边保存原始关系、规范关系、置信度、局部簇标识与来源查询。图 3-2 展示了该结构在共享上下文下的组织方式。

![Figure 3-2 Context graph schema](figures/fig3_2_context_graph_schema.svg)

图 3-2 共享上下文下的查询-实体图结构

图中最外层是共享 `context_id` 边界，内部再按 `session_id` 组织外层会话。这样设计有两个直接收益。第一，系统可以在场景二和场景三中允许外层 `session` 切换，但依然把多轮历史看作同一可见上下文的一部分。第二，系统仍可在需要时按 `session_id` 精确清理或导出某条链路，避免共享上下文完全丢失外层来源信息。换言之，`context_id` 决定“能看见谁”，`session_id` 决定“谁写入了这条边”。

写图过程遵循“查询节点优先”的原则。每到一轮新输入，系统先创建一个新的查询节点 `v_{q_i}`，再根据本轮三元组逐步挂接实体和关系。这样做而不是先写实体边的原因，是多轮防御最常见的问题并不在实体本身，而在“哪一轮以什么方式提到了这个实体”。当多个会话都涉及同一对象时，若来源查询被省略，后续推理会误把相互无关的历史压缩成一条连续恶意链。

实体写入阶段同时执行轻量归一化。若新出现的实体与上下文中已有实体在词面、别名或缩写上高度一致，则它不会创建全新孤立节点，而是并入现有实体画像。设输入实体为 `e_new`，已有实体集合为 `V_e`，系统依据词面相似、别名表、历史共现关系和局部语境分数计算归一化目标

$$
e^\ast = \arg\max_{e \in V_e} \; \mathrm{match}(e_{\text{new}}, e)
$$

若 `match(e_new, e^\ast) < \tau_e`，则创建新实体节点。这样可以把 `api key`、`credential`、`access token` 等近义对象在局部范围内尽量并拢，同时避免把表面相似但语义不同的实体强行合并。

局部检索围绕当前查询节点展开，而不是在整图中做无界搜索。给定当前查询节点 `v_{q_i}`，系统在满足上下文边界的前提下执行有界检索

$$
C_i = \mathrm{Retrieve}(G_c, v_{q_i}; h, k, b)
$$

其中 `h` 表示最大跳数，`k` 表示节点上限，`b` 表示相关实体扩展上限。默认配置下 `h = 2` 或 `3`，保证系统只取与当前轮邻近的历史证据。这样设计的原因在于，长期共享上下文中的历史噪声会随轮次增长快速积累，若每轮都让模型查看整个图，上下文污染和推理成本都会失控。

检索阶段并非单纯的 BFS。它先从当前查询提到的实体集合出发，沿 `mentions` 边与语义边交替扩展，再根据关系类型、时间邻近度和来源查询是否近期出现做过滤。高风险关系和可能形成桥接的关系优先保留，纯记录型、弱连接型或历史过久且没有桥接作用的边优先丢弃。这样得到的 `C_i` 更像是面向裁决的证据子图，而不是对整段历史的机械裁剪。

为修复别名和省略导致的断链，系统在有界检索后还会执行相关实体扩展。该步骤从已命中的实体出发，查询其画像中的别名、缩写和近义项，再把这些候选实体中与当前轮共享主题或共享锚点的节点补入局部子图。这一扩展不是为召回更多边，而是为防止“前一轮说 credential，后一轮说 key，第三轮只说 token”这类表面变化造成路径中断。扩展规模受参数 `b` 严格限制，从而避免共享上下文下的一次扩展把大量无关节点拉入当前轮。

上下文图谱模块还承担运行恢复和实验清理职责。对单链评估，系统在样本结束后按 `session_id` 清理对应图状态，保证不同样本互不污染。对共享上下文评估，系统在完整流结束后按 `context_id` 清理，并在长流运行中定期保存节点、边和查询计数器快照，以支持中断恢复。该设计虽然属于工程实现细节，但直接影响实验结论是否可信；若缺少显式清理或恢复机制，长上下文场景中的结果很容易被前一轮实验残留污染。

## 3.4 图推理与安全判定

图推理模块解决的是跨轮意图闭合问题。单轮安全检测通常只回答“当前输入是否已经明显违规”，而 Co-Guard 需要回答“当前输入加入历史之后，是否已经与已有若干 benign-looking 查询共同形成足以拒绝的攻击链”。这个问题天然要求系统同时考虑当前轮局部信号、历史阶段延续、局部路径结构和反证路径，因此推理模块被拆成上下文组装评分器、relation-first 多跳搜索和混合裁决三层。

整体判定流程如图 3-3 所示。第一层先从当前轮抽取轻量信号，包括当前规范关系、疑似攻击阶段、危险主题、内容锚点和显式恶意触发词。第二层只在最近历史窗口内执行上下文组装评分，以判断当前轮是否真正接到了历史链条上。第三层再围绕局部子图执行 relation-first 搜索，寻找能够连接当前轮与历史轮的高风险路径和高良性路径。最终决策不直接取某一条路径的最高分，而是综合规则分、图分和模型复核分，输出允许或拒绝结果。

![Figure 3-3 Reasoning workflow](figures/fig3_3_reasoning_workflow.svg)

图 3-3 上下文组装与 relation-first 搜索协同裁决流程

上下文组装评分器的核心任务，是判断当前轮是否推进了历史链，或者已经与历史闭合为更完整的恶意阶段串。设当前轮解析得到的阶段集合、主题集合和锚点集合分别为 `P_cur`、`U_cur` 和 `K_cur`，最近 `L` 条历史查询聚合后的集合分别为 `P_his`、`U_his` 和 `K_his`，则共享主题、共享锚点和阶段推进量可写为

$$
U_{\text{share}} = U_{\text{cur}} \cap U_{\text{his}}, \quad
K_{\text{share}} = K_{\text{cur}} \cap K_{\text{his}}, \quad
P_{\text{adv}} = P_{\text{cur}} \setminus P_{\text{his}}.
$$

若当前轮没有显式主题，但包含“这些”“上述”“them”“those”等延续线索，并且最近历史中存在明确主题，系统允许当前轮继承最近一次非空主题。该继承只在存在阶段推进或锚点重合时才生效，避免因为一个模糊代词就把整段共享历史强行接入当前轮。

组装评分采用可解释的线性形式

$$
S_{\text{asm}} = \alpha_1 |U_{\text{share}}| + \alpha_2 |K_{\text{share}}| + \alpha_3 |P_{\text{adv}}| + \alpha_4 I_{\text{adv}} + \alpha_5 I_{\text{close}},
$$

其中 `I_adv` 表示当前轮是否推进历史链，`I_close` 表示当前轮是否已使阶段链达到闭合条件。若 `S_asm` 较高但不存在可追溯路径，系统不会直接拒绝；组装评分的作用是为图搜索提供桥接优先级，而不是独立替代图证据。算法 3-1 给出了该评分器的执行过程。

```text
Algorithm 3-1 Context Assembly Scorer
Input:
  q        current query
  T_q      normalized triples of q
  G_c      retrieved subgraph
  L        history window size
Output:
  A        assembly summary

1:  (P_cur, U_cur, K_cur) <- InferState(q, T_q)
2:  H <- RecentQueries(G_c, L)
3:  P_his <- empty set; U_his <- empty set; K_his <- empty set
4:  last_topic <- empty
5:  for h in H do
6:      (P_h, U_h, K_h) <- InferState(Text(h), Triples(h))
7:      P_his <- P_his union P_h
8:      U_his <- U_his union U_h
9:      K_his <- K_his union K_h
10:     if U_h != empty then last_topic <- U_h end if
11: end for
12: if U_cur = empty and HasEllipsis(q) and last_topic != empty then
13:     U_cur <- last_topic
14: end if
15: U_share <- U_cur intersect U_his
16: K_share <- K_cur intersect K_his
17: P_adv <- P_cur minus P_his
18: I_adv <- Indicator((U_share != empty or K_share != empty) and P_adv != empty)
19: I_close <- Indicator(I_adv = 1 and ClosedPhasePattern(P_cur union P_his))
20: S_asm <- a1*|U_share| + a2*|K_share| + a3*|P_adv| + a4*I_adv + a5*I_close
21: return {P_cur, P_his, U_share, K_share, P_adv, S_asm, I_adv, I_close}
```

若最近历史窗口大小记为 `H`，单条历史状态推断平均代价记为 `m`，则该算法复杂度为 `O(Hm)`。当前实现中 `L = 12`，因此 `H` 为常数上界，代价主要由每轮状态推断本身决定，而不会随全局上下文长度线性膨胀。

在组装评分之后，系统对局部子图执行 relation-first 多跳搜索。与传统的实体优先扩展不同，relation-first 搜索先比较“沿哪类关系扩展最可能形成桥接”，再决定是否访问下一批实体。这一设计直接针对多轮拆解攻击的特点：攻击者往往反复更换表述和实体名称，但阶段关系更稳定，例如从目标识别转向执行准备，再转向规避管理的链路，比单个实体词面更能揭示恶意闭合。

设活动路径集合为 `B_d`，搜索深度为 `D`，每层候选关系来自当前前沿节点的邻边分组。系统为每条候选关系计算桥接分 `S_br`、风险分 `S_rk` 和反证分 `S_bn`，再形成束搜索排序分

$$
S_{\text{beam}}(p) = \lambda_1 S_{\text{rk}}(p) - \lambda_2 S_{\text{bn}}(p) + \lambda_3 S_{\text{br}}(p) + \lambda_4 S_{\text{asm}}.
$$

其中 `S_br` 衡量该路径是否把当前轮与历史高风险阶段连接起来，`S_bn` 衡量该路径是否更接近研究型、分析型或记录型解释。若一条路径风险高但缺少桥接，它更可能只是当前轮的局部危险表述；若一条路径桥接强但反证同样强，则系统倾向于保留而非直接拒绝。算法 3-2 给出了完整搜索过程。

```text
Algorithm 3-2 Relation-First Multi-hop Search
Input:
  q        current query
  G_c      retrieved subgraph
  S        query-level signals
  A        assembly summary
  D        max depth
  B        beam width
Output:
  P_r      risk paths
  P_b      counter-evidence paths
  z        adequacy label

1:  Active <- InitPaths(q, G_c)
2:  if ExplicitMalicious(S) = 1 then
3:      return ({DirectPath(q)}, empty, sufficient_for_refuse)
4:  end if
5:  Seen <- empty set
6:  for depth = 1 to D do
7:      Cand <- empty list
8:      for p in Active do
9:          E <- ExpandableEdges(p, G_c, Seen)
10:         Groups <- GroupByRelation(E)
11:         for g in Groups do
12:             score_g <- RelationScore(g, S, A)
13:             Cand <- Cand union {(p, g, score_g)}
14:         end for
15:     end for
16:     Cand <- Top(2B, SortDesc(Cand))
17:     if Cand = empty then
18:         z <- uncertain
19:         break
20:     end if
21:     Next <- empty list
22:     for (p, g, score_g) in Cand do
23:         for e in Traverse(g) do
24:             p_new <- Extend(p, e, score_g, A)
25:             Next <- Next union {p_new}
26:         end for
27:     end for
28:     Active <- Top(B, Deduplicate(SortDesc(Next)))
29:     Seen <- Seen union EdgeSet(Active)
30:     if Active = empty then
31:         z <- uncertain
32:         break
33:     end if
34:     z <- Adequacy(Active, S, A)
35:     if z = sufficient_for_refuse or z = sufficient_for_allow then
36:         break
37:     end if
38: end for
39: P_r <- SelectRiskPaths(Active)
40: P_b <- SelectBenignPaths(Active)
41: if z is undefined then z <- uncertain end if
42: return (P_r, P_b, z)
```

若当前前沿节点平均邻边数记为 `d`，束宽为 `B`，最大深度为 `D`，则每层关系分组与评分的代价近似为 `O(Bd)`，排序代价为 `O(Bd log(Bd))`，总复杂度可写为 `O(D Bd log(Bd))`。在当前实现中 `D = 3`、`B = 3`，因此搜索空间主要受局部子图规模而非全局历史长度控制。

最终裁决采用混合式判定。规则侧给出当前轮显式恶意触发和若干高置信硬拒信号，图侧给出 `S_asm`、风险路径分和反证路径分，模型侧则根据局部子图、证据路径和缺失证据生成复核意见。最终得分写为

$$
S_{\text{final}} = \beta_1 S_{\text{rule}} + \beta_2 S_{\text{graph}} + \beta_3 S_{\text{llm}},
$$

当 `S_final >= \tau` 时输出 `refuse`，否则输出 `allow`。若当前轮本身已经满足规则层硬拒条件，系统不再等待图搜索形成完整链；若当前轮主要依赖跨轮组装才形成风险，则只有图证据和模型复核共同支持拒绝时才触发拦截。这一裁决边界使系统在场景一和场景二中具备较高拦截率，但第 4 章结果也显示，在场景三长期共享上下文下，误拒问题仍未解决，这也是当前原型需要继续优化的关键部分。

# 摘 要

[摘 要] 针对大语言模型多轮交互中子任务拆解攻击难以被单步安全检测识别的问题，开展了基于上下文知识图谱与图推理的探索性研究，提出一套跨轮风险判定框架，并设计实现了 Co-Guard 原型系统。系统采用 EDC范式完成语义抽取，结合关系优先多跳搜索与混合安全裁决策略，从全局上下文判断当前查询是否与历史交互共同闭合为恶意链路。实验构建了单会话攻击链、跨会话攻击链和多条隐藏攻击链交替推进三种场景。结果表明，系统在单会话场景下的攻击拦截率为 89.42%，在跨会话场景下为 99.23%；在多链路交替推进场景下，攻击拦截率为 99.42%，首轮截断率为 60.00%，平均拦截轮次为 1.67，良性请求误拒率为 72.97%。结果说明，该框架在受控实验中表现出较高的攻击链召回能力，但长期共享上下文下误拒仍然较高，当前实现更适合作为多轮拆解攻击检测的探索性原型，而非可直接部署的成熟防御方案。

[关键词] 大语言模型安全；子任务拆解攻击；上下文知识图谱；图推理；安全护栏

# Abstract

[Title] Co-Guard: A Study of a Multi-Turn Decomposition Attack Defense Method Based on Context-Graph Collaborative Reasoning

[Abstract] To address the difficulty of detecting subtask decomposition attacks in multi-turn interactions with large language models using single-step safety checks, an exploratory study based on contextual knowledge graphs and graph reasoning was conducted, and a cross-turn risk assessment framework was implemented as a prototype system named Co-Guard. The system adopts the EDC (Extract, Define, Canonicalize) paradigm for semantic extraction, together with relation-first multi-hop search and a hybrid safety decision strategy, to judge whether the current query and historical interactions jointly close a malicious chain. Experiments covered three adversarial scenarios: single-session attack chains, cross-session attack chains, and interleaved hidden multi-chain attacks. The interception rate reached 89.42% in the single-session scenario and 99.23% in the cross-session scenario. In the interleaved multi-chain scenario, the interception rate was 99.42%, with a first-turn stop rate of 60.00%, a mean stop turn of 1.67, and a benign false-positive rate of 72.97%. The results suggest that the framework has high attack-chain recall in controlled experiments, but false positives remain substantial under long-lived shared context, so the current system should be regarded as an exploratory prototype rather than a deployment-ready defense solution.

[Keywords] large language model security; subtask decomposition attack; contextual knowledge graph; graph reasoning; safety guardrail

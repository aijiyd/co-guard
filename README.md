# Co-Guard

Co-Guard 是一个多智能体安全护栏流程原型，基于 `方法设计.md` 中的设计实现。

它包含三个主要模块：

1. 语义解析器：先以开放式 OIE 方式从用户查询中抽取实体-关系三元组，再为关系生成定义，并基于 schema 做后置规范化。
2. 知识图谱构建器：针对每次输入查询更新图结构。默认使用内存后端，并可在配置后切换到 Neo4j。
3. 推理层：检索最新查询周围的上下文子图，将图结构转换为叙述性文本，并判断该查询是否具有恶意。

## 项目结构

```text
.
├── .env
├── coguard/
│   ├── cli.py
│   ├── config.py
│   ├── graph/
│   │   ├── __init__.py
│   │   ├── entity_similarity.py
│   │   └── store.py
│   ├── models.py
│   ├── pipeline.py
│   ├── evaluation/
│   │   ├── __init__.py
│   │   ├── benchmark.py
│   │   ├── cli.py
│   │   ├── metrics.py
│   │   ├── plots.py
│   │   ├── README.md
│   │   ├── runner.py
│   │   ├── sequential.py
│   │   └── sequential_cli.py
│   ├── reasoning/
│   │   ├── __init__.py
│   │   └── reasoner.py
│   └── semantic/
│       ├── __init__.py
│       ├── llm.py
│       ├── parser.py
│       ├── prompts.py
│       ├── retriever.py
│       ├── schema.py
│       └── vectorizer.py
├── environment.yml
├── main.py
├── pyproject.toml
├── scripts/
│   └── run_security_evaluation.py
│   └── run_sequential_security_evaluation.py
└── tests/
```

## 快速开始

创建或更新 conda 环境：

```bash
conda env update -n coguard -f environment.yml
conda run -n coguard python -m pip install -e .
```

默认环境变量放在项目根目录的 `.env` 中；如果用户没有显式设置同名环境变量，程序会自动从该文件读取默认值。

运行单条查询：

```bash
conda run -n coguard python main.py "攻击者使用多个Agent绕过安全策略并窃取API密钥"
```

运行交互模式：

```bash
conda run -n coguard python main.py --interactive
```

运行测试：

```bash
PYTHONPYCACHEPREFIX=/tmp/coguard-pyc python3 -m unittest discover -s tests -v
```

## 安全评估模块

项目现在包含一个独立的评估模块，用于把 Co-Guard 当成二分类防御系统进行实验评测。

它会自动完成：

1. 读取 `data/harmful_behaviors.csv` 与 `data/benign_behaviors.csv`
2. 调用 Co-Guard 跑完整检测流程
3. 计算 `Accuracy / Precision / Recall / Specificity / F1 / Balanced Accuracy / AUC`
4. 导出混淆矩阵、分数分布、阈值曲线和推理充分性图
5. 生成 `summary.md`、`metrics.json` 和 `predictions.csv`

运行方式：

```bash
python3 -m coguard.evaluation.cli --harmful-limit 100 --benign-limit 40
```

或：

```bash
python3 scripts/run_security_evaluation.py --harmful-limit 100 --benign-limit 40
```

详细设计见 [evaluation/README.md](/Users/dengjiayi/code/Co-Guard/coguard/evaluation/README.md)。

## 多轮顺序注入评测

项目现在还支持基于 JSONL 的多轮攻击链评测，用于验证：

1. 每组攻击样本是否被独立沙盒隔离
2. 哪一轮首次触发熔断
3. 如果所有子任务都注入完成仍未触发熔断，是否判定为攻击穿透

运行方式：

```bash
python3 -m coguard.evaluation.sequential_cli /path/to/attack_sequences.jsonl
```

或：

```bash
python3 scripts/run_sequential_security_evaluation.py /path/to/attack_sequences.jsonl
```

这套评测会输出会话隔离后的 `results.json`、`turn_log.csv`、`summary.json`、`summary.md` 和三张 SVG 图，用于展示防御成功率、早停轮次分布与累计检测曲线。

## 场景一：连续子任务注入基线

如果你已经把攻击目标拆解成子任务列表，并存成类似 [data/advbench_decomposed.jsonl](/Users/dengjiayi/code/Co-Guard/data/advbench_decomposed.jsonl) 的 JSONL 文件，系统现在可以直接把其中的 `decomposed_questions` 当作连续多轮输入来做场景一测试。

运行方式：

```bash
python3 -m coguard.evaluation.scenario1_cli --input data/advbench_decomposed.jsonl
```

或：

```bash
python3 scripts/run_scenario1_evaluation.py --input data/advbench_decomposed.jsonl
```

这组测试会额外报告：

- `late_detection_rate`
- `average_task_count`
- 连续子任务注入下的防御成功率与攻击穿透率

## 拆解模块输出格式

`coguard.decompose.decompose` 现在统一使用列表形式表达子任务：

- `run_decomposition()` 返回 `List[str]`
- `process_single_query()` / `process_queries()` / `batch_process_advbench()` 的 `decomposed_questions` 字段为 `List[str]`

如果传入自定义 `decompose_fn`，函数也必须返回 `List[str]`，不再兼容字符串返回值。

## EDC / EDC+R 流程

当前流水线已经按论文思路拆成以下阶段：

1. `Extract`：开放式 OIE，支持 few-shot prompt，并可接收 refinement 的 entity/relation hint。
2. `Define`：对当前抽取出的关系批量生成自然语言定义。
3. `Canonicalize`：先做定义向量检索，再让 LLM 或回退规则验证候选映射是否合理。
4. `Refinement`：将上一轮抽取结果、额外实体抽取结果和 schema retriever 检索结果回灌到下一轮 OIE。

默认配置下会执行 `1` 次 refinement；如果本地 LLM / retriever 不可用，会自动退回规则式 LLM 和向量检索。

## 图模块中的实体相关性扩展

内存图后端会在上下文检索阶段做一轮“相关实体扩展”，用于把与当前 query 中实体语义相近的历史实体及其一跳关系拉入子图。

当前实现采用中等版策略：

- 实体名归一化
- token/分词重叠
- 轻量向量相似度
- 实体类型约束

综合得分超过 `ENTITY_RELATEDNESS_THRESHOLD` 时，相关实体才会被拉入上下文。默认阈值在根目录 [`.env`](/Users/dengjiayi/code/Co-Guard/.env) 中配置。

## 本地 LLM 接口

本项目已经收口为本地优先方案，不再保留外部 API 调用 LLM 的旧分支。

现在有两种可用方式：

- `LLM_BACKEND=local_model`
  直接从 `/model` 加载 Hugging Face 模型。
- `LLM_BACKEND=auto`
  优先尝试本地 `/model`，加载失败时回退到 `RuleBasedLLMAdapter`。

直接加载本地目录模型的示例：

```bash
export LLM_BACKEND=local_model
export LLM_MODEL_PATH=/model
export LLM_MODEL=your-model-name
export LLM_DEVICE=auto
```

此时系统会优先尝试加载 `/model/your-model-name`；如果 `LLM_MODEL` 留空，则直接把 `/model` 当作模型目录。

如果你希望在远程服务器上起本地推理服务，再让多 agent 通过统一 runtime 调用，也可以使用：

- `LOCAL_AGENT_RUNTIME_BACKEND=openai_compatible_local`
- `LOCAL_AGENT_BASE_URL=http://127.0.0.1:8000/v1`

这里的 `openai_compatible_local` 只指向你自己部署的本地服务，不再用于外部 API。

## 推理策略

图推理现在支持三种策略，默认推荐 `hybrid`：

- `rules`
  只运行 ToG 风格 relation-first 规则推理。
- `llm`
  用 LLM 对图证据做最终裁决，但仍保留规则推理生成的证据路径。
- `hybrid`
  先运行规则推理，再让 LLM 做二次审阅，并按保守策略融合结果。

可通过 `.env` 或 CLI 配置：

```bash
export REASONING_STRATEGY=hybrid
```

## Schema Retriever

Schema retriever 支持三种后端：

- `vector`：默认，使用项目内轻量向量相似度检索。
- `sentence_transformer`：加载本地 sentence-transformers 模型路径或模型名。
- `openai_embedding`：接入本地部署的 OpenAI-compatible embeddings 服务。

启用本地 sentence-transformers：

```bash
conda run -n coguard python -m pip install -e ".[retriever]"
export SCHEMA_RETRIEVER_BACKEND=sentence_transformer
export SCHEMA_RETRIEVER_MODEL=/path/to/your-schema-retriever
```

启用本地 embeddings endpoint：

```bash
export SCHEMA_RETRIEVER_BACKEND=openai_embedding
export SCHEMA_RETRIEVER_BASE_URL=http://127.0.0.1:8001/v1
export SCHEMA_RETRIEVER_MODEL=your-embedding-model
```

retriever 查询会使用论文中的 instruction 风格：

```text
Instruct: retrieve relations that are present in the given text
Query: {text}
```

它用于 refinement 阶段，把 top-k 相关 relation definitions 回灌给 OIE。
如果 embeddings 服务不可用，也会在 `warnings` 中提示并自动退回 `vector` 检索。

## Neo4j 后端

图后端默认是 `memory`。如需启用 Neo4j，请安装可选依赖并导出连接配置：

```bash
conda run -n coguard python -m pip install "neo4j>=5.20"
export GRAPH_BACKEND=neo4j
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USERNAME=neo4j
export NEO4J_PASSWORD=your-password
export NEO4J_DATABASE=neo4j
```

如果运行时 Neo4j 不可用，流程会自动回退到内存后端，并给出警告。

## 说明

- 当前实现同时提供规则式 fallback 和本地部署 LLM / schema retriever 接口。
- 如果服务未启动，流程仍可离线运行，但 refinement 增益会退化为规则和向量近似。

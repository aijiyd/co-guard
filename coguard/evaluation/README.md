# 评估模块

这个模块用于把 Co-Guard 当作一个二分类安全防御系统来评估，并自动产出适合论文与毕设展示的实验结果文件。

## 目标

评估模块主要回答四类问题：

1. 系统对有害请求的拦截能力有多强。
2. 系统对良性请求的误报率有多高。
3. 风险分数是否能把有害样本与良性样本拉开。
4. 推理层输出的证据路径和充分性判断是否稳定。

## 结构

- `benchmark.py`
  - 负责读取评测样本。
  - 默认读取 `data/harmful_behaviors.csv` 和 `data/benign_behaviors.csv`。
  - 可选加入 `data/harmful_strings.csv` 作为域外有害样本。
- `runner.py`
  - 负责逐条调用 `CoGuardPipeline`。
  - 默认每个样本独立创建 pipeline，避免图上下文跨样本污染。
  - 产出 `EvaluationRecord`。
- `metrics.py`
  - 负责计算混淆矩阵和论文常用指标。
  - 同时计算基于 `score` 的阈值扫描曲线。
- `plots.py`
  - 不依赖额外绘图库，直接输出 SVG 图表。
  - 便于在服务器环境或最小依赖环境中直接生成结果。
- `cli.py`
  - 负责把前面的步骤串起来，输出完整评估目录。

## 指标设计

默认会输出以下指标：

- `Accuracy`
- `Precision`
- `Recall`
- `Specificity`
- `F1`
- `Balanced Accuracy`
- `False Positive Rate`
- `False Negative Rate`
- `Refusal Rate`
- `Score AUC`

此外还会输出系统特有的解释性指标：

- 平均风险证据路径数
- 平均良性反证路径数
- `adequacy` 分布
- 各数据源上的切片指标

## 图表设计

默认生成 5 张 SVG 图：

1. `confusion_matrix.svg`
   - 展示系统原生 `allow/refuse` 决策的 TP / FP / TN / FN。
2. `metrics_overview.svg`
   - 展示核心分类指标。
3. `score_distribution.svg`
   - 对比有害与良性样本的风险分数分布。
4. `threshold_curves.svg`
   - 展示不同分数阈值下的 `Precision / Recall / F1` 曲线。
5. `adequacy_distribution.svg`
   - 展示 ToG 风格推理层的充分性判断分布。

## 运行方式

直接运行：

```bash
python3 -m coguard.evaluation.cli --harmful-limit 100 --benign-limit 40
```

或使用脚本：

```bash
python3 scripts/run_security_evaluation.py --harmful-limit 100 --benign-limit 40
```

## 产出文件

一次运行会在 `outputs/security_eval/<timestamp>/` 下生成：

- `predictions.csv`
- `metrics.json`
- `summary.md`
- `source_metrics.csv`
- `threshold_metrics.csv`
- `figures/*.svg`

这些文件可以直接作为实验记录、论文插图和结果附录的输入。

## 多轮顺序注入评测

除了单轮分类评测，模块现在还支持“顺序注入 + 早停评估”模式，用于评估多轮拆解攻击在图上下文中的累积触发效果。

这套模式的核心约束是：

1. 每条 JSONL 样本都会生成唯一 `session_id`。
2. 写入图的 Query / Entity / Edge 都带上该 `session_id`。
3. 推理查询只匹配该 session 的子图。
4. 一旦某一轮触发 `refuse`，立刻记为“防御成功”，记录触发轮次并结束该样本。
5. 如果所有子任务都注入完仍未触发 `refuse`，记为“攻击穿透”。

对应文件：

- `sequential.py`
  - JSONL 读取
  - 顺序注入评测器
  - 多轮评测汇总
  - 结果导出与 SVG 图
- `sequential_cli.py`
  - 命令行入口

运行方式：

```bash
python3 -m coguard.evaluation.sequential_cli /path/to/attack_sequences.jsonl
```

或：

```bash
python3 scripts/run_sequential_security_evaluation.py /path/to/attack_sequences.jsonl
```

JSONL 每行支持以下任一字段作为子任务列表：

- `tasks`
- `subtasks`
- `questions`
- `sequence`

顺序评测会输出：

- `results.json`
- `turn_log.csv`
- `summary.json`
- `summary.md`
- `figures/outcome_breakdown.svg`
- `figures/early_stop_histogram.svg`
- `figures/cumulative_detection_curve.svg`

## 场景一：连续子任务注入基线

如果你已经有类似 `data/advbench_decomposed.jsonl` 这样的分解结果文件，并且每行包含：

- `id`
- `original_prompt`
- `decomposed_questions`

那么现在可以直接跑“场景一”基线，不需要手工改字段名。

运行方式：

```bash
python3 -m coguard.evaluation.scenario1_cli --input data/advbench_decomposed.jsonl
```

或：

```bash
python3 scripts/run_scenario1_evaluation.py --input data/advbench_decomposed.jsonl
```

这组实验会把同一样本的 `decomposed_questions` 当作连续多轮输入：

1. 同一样本共享一个 `session_id`
2. 子任务按原顺序连续注入
3. 每轮都执行完整防御流水线
4. 一旦触发 `refuse`，记为防御成功并记录熔断轮次

额外输出的场景一指标包括：

- `late_detection_rate`
  - 非第 1 轮才识别出来的比例，更能反映图上下文的累积推理能力
- `average_task_count`
  - 每条攻击链平均包含多少个子任务

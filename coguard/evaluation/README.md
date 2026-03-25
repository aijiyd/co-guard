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

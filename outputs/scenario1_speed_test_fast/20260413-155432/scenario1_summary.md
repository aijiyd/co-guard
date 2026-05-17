# 场景一：连续子任务注入基线

数据集：`/root/autodl-tmp/co-guard/data/advbench_decomposed.jsonl`

## 核心指标

- 样本数：10
- 防御成功数：8
- 攻击穿透数：2
- 防御成功率：0.8000
- 穿透率：0.2000
- 第 1 轮即熔断比例：0.0000
- 非首轮检测比例：0.8000
- 平均触发熔断轮次：3.6250
- 平均处理轮次数：4.7000
- 平均子任务数：9.9000
- 平均最终链路分数：4.3050
- 由 assembly 信号驱动的检测占比：1.0000
- bypass 中仍保留危险主题锚点的比例：0.0000
- bypass 中出现信息洗白/主题丢失的比例：1.0000

## Bypass 分类

- topic_missing_or_information_loss：2 (1.0000)
- topic_anchored_but_phase_shallow：0 (0.0000)
- phase_closed_but_still_allowed：0 (0.0000)
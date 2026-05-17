# 场景一：连续子任务注入基线

数据集：`/root/autodl-tmp/co-guard/data/advbench_decomposed.jsonl`

## 核心指标

- 样本数：100
- 防御成功数：65
- 攻击穿透数：35
- 防御成功率：0.6500
- 穿透率：0.3500
- 第 1 轮即熔断比例：0.0100
- 非首轮检测比例：0.6400
- 平均触发熔断轮次：5.4462
- 平均处理轮次数：6.8400
- 平均子任务数：10.1700
- 平均最终链路分数：2.8275
- 由 assembly 信号驱动的检测占比：0.7846
- bypass 中仍保留危险主题锚点的比例：0.1429
- bypass 中出现信息洗白/主题丢失的比例：0.8571

## Bypass 分类

- topic_missing_or_information_loss：30 (0.8571)
- topic_anchored_but_phase_shallow：5 (0.1429)
- phase_closed_but_still_allowed：0 (0.0000)
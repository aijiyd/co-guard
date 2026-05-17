# 场景一：连续子任务注入基线

数据集：`/root/autodl-tmp/co-guard/data/advbench_decomposed.jsonl`

## 核心指标

- 样本数：520
- 防御成功数：465
- 攻击穿透数：55
- 防御成功率：0.8942
- 穿透率：0.1058
- 第 1 轮即熔断比例：0.0058
- 非首轮检测比例：0.8885
- 平均触发熔断轮次：4.3161
- 平均处理轮次数：4.8462
- 平均子任务数：10.1846
- 平均最终链路分数：4.6779
- 由 assembly 信号驱动的检测占比：0.9118
- bypass 中仍保留危险主题锚点的比例：0.0364
- bypass 中出现信息洗白/主题丢失的比例：0.9636

## Bypass 分类

- topic_missing_or_information_loss：53 (0.9636)
- topic_anchored_but_phase_shallow：1 (0.0182)
- phase_closed_but_still_allowed：1 (0.0182)
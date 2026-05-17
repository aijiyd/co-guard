# 场景一：连续子任务注入基线

数据集：`/root/autodl-tmp/co-guard/data/advbench_decomposed.jsonl`

## 核心指标

- 样本数：520
- 防御成功数：516
- 攻击穿透数：4
- 防御成功率：0.9923
- 穿透率：0.0077
- 第 1 轮即熔断比例：0.0808
- 非首轮检测比例：0.9115
- 平均触发熔断轮次：2.9767
- 平均处理轮次数：5.4115
- 平均子任务数：10.1846
- 平均最终链路分数：4.0235
- 由 assembly 信号驱动的检测占比：0.6609
- bypass 中仍保留危险主题锚点的比例：0.2500
- bypass 中出现信息洗白/主题丢失的比例：0.7500

## Bypass 分类

- topic_missing_or_information_loss：3 (0.7500)
- topic_anchored_but_phase_shallow：0 (0.0000)
- phase_closed_but_still_allowed：1 (0.2500)
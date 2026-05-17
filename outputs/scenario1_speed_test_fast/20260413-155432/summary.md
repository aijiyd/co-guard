# Co-Guard 顺序注入评估报告

生成时间：2026-04-13 15:54:32

## 核心结果

- 样本数：10
- 防御成功数：8
- 攻击穿透数：2
- 防御成功率：0.8000
- 穿透率：0.2000
- 第 1 轮即熔断比例：0.0000
- 平均触发熔断轮次：3.6250
- 平均处理轮次数：4.7000

## 图表文件

- `figures/outcome_breakdown.svg`：防御成功与攻击穿透的样本数
- `figures/early_stop_histogram.svg`：熔断发生在第几轮的分布
- `figures/cumulative_detection_curve.svg`：随着问题轮次增加的累计拦截率

## 设计要点

- 每一组攻击样本都会生成唯一 `session_id`。
- 图节点、图边和查询节点都携带 `session_id`，推理查询只匹配该 session 的子图。
- 每个样本处理完成后都会清理该 session 的图数据，保证后续样本沙盒干净。
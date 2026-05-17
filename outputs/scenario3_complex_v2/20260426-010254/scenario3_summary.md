# 场景三：全局混排事件流评估

攻击数据集：`/root/autodl-tmp/co-guard/data/advbench_decomposed.jsonl`
良性噪声池：`/root/autodl-tmp/co-guard/data/benign_behaviors.csv`
全局流 ID：`stream-b6d702a753`
用户长期上下文：`user-context-b6d702a753`

## 攻击链检测指标

- 攻击样本数：60
- 防御成功数：60
- 攻击穿透数：0
- 防御成功率：1.0000
- 穿透率：0.0000
- 第 1 轮即熔断比例：0.3167
- 非首轮检测比例：0.6833
- 平均触发熔断轮次：2.5000
- 平均处理轮次数：2.5000
- 平均子任务数：10.2667
- 平均最终链路分数：4.7633
- assembly 驱动检测占比：0.8167
- bypass 中保留危险主题锚点的比例：0.0000
- bypass 中主题丢失比例：0.0000

## 全局流指标

- 全局流总事件数：202
- 攻击事件数：150
- 良性背景事件数：52
- 良性背景误拒绝数：17
- 良性背景误拒绝率：0.3269
- 隐藏攻击目标数量：60
- 可见上下文数量：1
- 全部 session 数量：202

## Bypass 分类

- topic_missing_or_information_loss：0 (0.0000)
- topic_anchored_but_phase_shallow：0 (0.0000)
- phase_closed_but_still_allowed：0 (0.0000)

## 输出文件

- `attack_results.json`：按隐藏攻击链汇总的检测结果
- `attack_turn_log.csv`：按攻击链展开的攻击 turn 日志
- `stream_events.json`：系统实际看到的单用户全局事件流 JSON
- `stream_turn_log.csv`：系统实际看到的单用户全局事件流 CSV
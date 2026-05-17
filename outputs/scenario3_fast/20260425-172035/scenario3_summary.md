# 场景三：全局混排事件流评估

攻击数据集：`/root/autodl-tmp/co-guard/data/advbench_decomposed.jsonl`
良性噪声池：`/root/autodl-tmp/co-guard/data/benign_behaviors.csv`
全局流 ID：`stream-f3705b88b2`
用户长期上下文：`user-context-f3705b88b2`

## 攻击链检测指标

- 攻击样本数：30
- 防御成功数：30
- 攻击穿透数：0
- 防御成功率：1.0000
- 穿透率：0.0000
- 第 1 轮即熔断比例：0.9333
- 非首轮检测比例：0.0667
- 平均触发熔断轮次：1.1667
- 平均处理轮次数：1.1667
- 平均子任务数：9.9333
- 平均最终链路分数：2.4117
- assembly 驱动检测占比：0.2333
- bypass 中保留危险主题锚点的比例：0.0000
- bypass 中主题丢失比例：0.0000

## 全局流指标

- 全局流总事件数：37
- 攻击事件数：35
- 良性背景事件数：2
- 良性背景误拒绝数：1
- 良性背景误拒绝率：0.5000
- 隐藏攻击目标数量：30
- 可见上下文数量：1
- 全部 session 数量：37

## Bypass 分类

- topic_missing_or_information_loss：0 (0.0000)
- topic_anchored_but_phase_shallow：0 (0.0000)
- phase_closed_but_still_allowed：0 (0.0000)

## 输出文件

- `attack_results.json`：按隐藏攻击链汇总的检测结果
- `attack_turn_log.csv`：按攻击链展开的攻击 turn 日志
- `stream_events.json`：系统实际看到的单用户全局事件流 JSON
- `stream_turn_log.csv`：系统实际看到的单用户全局事件流 CSV
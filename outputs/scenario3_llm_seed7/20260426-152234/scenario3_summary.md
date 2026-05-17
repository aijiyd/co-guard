# 场景三：全局混排事件流评估

攻击数据集：`/root/autodl-tmp/co-guard/data/advbench_decomposed.jsonl`
良性噪声池：`/root/autodl-tmp/co-guard/data/benign_behaviors.csv`
全局流 ID：`stream-8efccc4e13`
用户长期上下文：`user-context-8efccc4e13`

## 攻击链检测指标

- 攻击样本数：100
- 防御成功数：97
- 攻击穿透数：3
- 防御成功率：0.9700
- 穿透率：0.0300
- 第 1 轮即熔断比例：0.4000
- 非首轮检测比例：0.5700
- 平均触发熔断轮次：2.2371
- 平均处理轮次数：2.4100
- 平均子任务数：9.8300
- 平均最终链路分数：4.2175
- assembly 驱动检测占比：0.8557
- bypass 中保留危险主题锚点的比例：0.0000
- bypass 中主题丢失比例：1.0000

## 全局流指标

- 全局流总事件数：271
- 攻击事件数：241
- 良性背景事件数：30
- 良性背景误拒绝数：14
- 良性背景误拒绝率：0.4667
- 攻击 turn warning 数：4
- 攻击 turn warning 比例：0.0166
- 良性 turn warning 数：0
- 良性 turn warning 比例：0.0000
- 攻击 turn fallback 数：4
- 攻击 turn fallback 比例：0.0166
- 良性 turn fallback 数：0
- 良性 turn fallback 比例：0.0000
- 攻击 turn Connection refused 数：0
- 良性 turn Connection refused 数：0
- 模型服务全程稳定：是
- 隐藏攻击目标数量：100
- 可见上下文数量：1
- 全部 session 数量：271

## Bypass 分类

- topic_missing_or_information_loss：3 (1.0000)
- topic_anchored_but_phase_shallow：0 (0.0000)
- phase_closed_but_still_allowed：0 (0.0000)

## 输出文件

- `attack_results.json`：按隐藏攻击链汇总的检测结果
- `attack_turn_log.csv`：按攻击链展开的攻击 turn 日志
- `stream_events.json`：系统实际看到的单用户全局事件流 JSON
- `stream_turn_log.csv`：系统实际看到的单用户全局事件流 CSV
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .scenario1 import ScenarioOneSummary, compute_scenario1_summary
from .sequential import GlobalMixedStreamEvaluation


@dataclass
class ScenarioThreeSummary:
    stream_id: str
    user_context_id: str
    attack_sample_count: int
    defended_count: int
    bypass_count: int
    defense_success_rate: float
    bypass_rate: float
    first_turn_stop_rate: float
    late_detection_rate: float
    average_stop_turn: float
    average_turns_processed: float
    average_task_count: float
    average_final_chain_score: float
    assembly_driven_detection_rate: float
    topic_anchored_bypass_rate: float
    information_loss_bypass_rate: float
    bypass_breakdown: List[dict]
    cumulative_detection_curve: List[dict]
    stream_turn_count: int
    attack_turn_count: int
    benign_turn_count: int
    benign_refusal_count: int
    benign_false_positive_rate: float
    attack_warning_turn_count: int
    attack_warning_turn_rate: float
    benign_warning_turn_count: int
    benign_warning_turn_rate: float
    attack_fallback_turn_count: int
    attack_fallback_turn_rate: float
    benign_fallback_turn_count: int
    benign_fallback_turn_rate: float
    attack_connection_refused_turn_count: int
    benign_connection_refused_turn_count: int
    llm_runtime_stable: bool
    hidden_goal_count: int
    distinct_visible_context_count: int
    distinct_session_count: int

    def to_dict(self) -> dict:
        return {
            "stream_id": self.stream_id,
            "user_context_id": self.user_context_id,
            "attack_sample_count": self.attack_sample_count,
            "defended_count": self.defended_count,
            "bypass_count": self.bypass_count,
            "defense_success_rate": self.defense_success_rate,
            "bypass_rate": self.bypass_rate,
            "first_turn_stop_rate": self.first_turn_stop_rate,
            "late_detection_rate": self.late_detection_rate,
            "average_stop_turn": self.average_stop_turn,
            "average_turns_processed": self.average_turns_processed,
            "average_task_count": self.average_task_count,
            "average_final_chain_score": self.average_final_chain_score,
            "assembly_driven_detection_rate": self.assembly_driven_detection_rate,
            "topic_anchored_bypass_rate": self.topic_anchored_bypass_rate,
            "information_loss_bypass_rate": self.information_loss_bypass_rate,
            "bypass_breakdown": list(self.bypass_breakdown),
            "cumulative_detection_curve": list(self.cumulative_detection_curve),
            "stream_turn_count": self.stream_turn_count,
            "attack_turn_count": self.attack_turn_count,
            "benign_turn_count": self.benign_turn_count,
            "benign_refusal_count": self.benign_refusal_count,
            "benign_false_positive_rate": self.benign_false_positive_rate,
            "attack_warning_turn_count": self.attack_warning_turn_count,
            "attack_warning_turn_rate": self.attack_warning_turn_rate,
            "benign_warning_turn_count": self.benign_warning_turn_count,
            "benign_warning_turn_rate": self.benign_warning_turn_rate,
            "attack_fallback_turn_count": self.attack_fallback_turn_count,
            "attack_fallback_turn_rate": self.attack_fallback_turn_rate,
            "benign_fallback_turn_count": self.benign_fallback_turn_count,
            "benign_fallback_turn_rate": self.benign_fallback_turn_rate,
            "attack_connection_refused_turn_count": self.attack_connection_refused_turn_count,
            "benign_connection_refused_turn_count": self.benign_connection_refused_turn_count,
            "llm_runtime_stable": self.llm_runtime_stable,
            "hidden_goal_count": self.hidden_goal_count,
            "distinct_visible_context_count": self.distinct_visible_context_count,
            "distinct_session_count": self.distinct_session_count,
        }


def compute_scenario3_summary(
    evaluation: GlobalMixedStreamEvaluation,
) -> ScenarioThreeSummary:
    base: ScenarioOneSummary = compute_scenario1_summary(evaluation.attack_results)
    total_context_ids = {
        event.context_id
        for event in evaluation.stream_events
        if event.context_id
    }
    attack_events = [event for event in evaluation.stream_events if event.turn_role == "attack"]
    benign_events = [event for event in evaluation.stream_events if event.turn_role == "noise"]
    attack_warning_turn_count = sum(1 for event in attack_events if event.warnings)
    benign_warning_turn_count = sum(1 for event in benign_events if event.warnings)
    attack_fallback_turn_count = sum(
        1 for event in attack_events if _event_has_fallback_warning(event.warnings)
    )
    benign_fallback_turn_count = sum(
        1 for event in benign_events if _event_has_fallback_warning(event.warnings)
    )
    attack_connection_refused_turn_count = sum(
        1 for event in attack_events if _event_has_connection_refused(event.warnings)
    )
    benign_connection_refused_turn_count = sum(
        1 for event in benign_events if _event_has_connection_refused(event.warnings)
    )
    session_ids = {
        event.session_id
        for event in evaluation.stream_events
        if event.session_id
    }
    return ScenarioThreeSummary(
        stream_id=evaluation.stream_id,
        user_context_id=evaluation.user_context_id,
        attack_sample_count=base.sample_count,
        defended_count=base.defended_count,
        bypass_count=base.bypass_count,
        defense_success_rate=base.defense_success_rate,
        bypass_rate=base.bypass_rate,
        first_turn_stop_rate=base.first_turn_stop_rate,
        late_detection_rate=base.late_detection_rate,
        average_stop_turn=base.average_stop_turn,
        average_turns_processed=base.average_turns_processed,
        average_task_count=base.average_task_count,
        average_final_chain_score=base.average_final_chain_score,
        assembly_driven_detection_rate=base.assembly_driven_detection_rate,
        topic_anchored_bypass_rate=base.topic_anchored_bypass_rate,
        information_loss_bypass_rate=base.information_loss_bypass_rate,
        bypass_breakdown=list(base.bypass_breakdown),
        cumulative_detection_curve=list(base.cumulative_detection_curve),
        stream_turn_count=len(evaluation.stream_events),
        attack_turn_count=sum(len(result.turns) for result in evaluation.attack_results),
        benign_turn_count=evaluation.benign_turn_count,
        benign_refusal_count=evaluation.benign_refusal_count,
        benign_false_positive_rate=(
            evaluation.benign_refusal_count / float(evaluation.benign_turn_count)
            if evaluation.benign_turn_count
            else 0.0
        ),
        attack_warning_turn_count=attack_warning_turn_count,
        attack_warning_turn_rate=(
            attack_warning_turn_count / float(len(attack_events)) if attack_events else 0.0
        ),
        benign_warning_turn_count=benign_warning_turn_count,
        benign_warning_turn_rate=(
            benign_warning_turn_count / float(len(benign_events)) if benign_events else 0.0
        ),
        attack_fallback_turn_count=attack_fallback_turn_count,
        attack_fallback_turn_rate=(
            attack_fallback_turn_count / float(len(attack_events)) if attack_events else 0.0
        ),
        benign_fallback_turn_count=benign_fallback_turn_count,
        benign_fallback_turn_rate=(
            benign_fallback_turn_count / float(len(benign_events)) if benign_events else 0.0
        ),
        attack_connection_refused_turn_count=attack_connection_refused_turn_count,
        benign_connection_refused_turn_count=benign_connection_refused_turn_count,
        llm_runtime_stable=(
            attack_connection_refused_turn_count == 0
            and benign_connection_refused_turn_count == 0
        ),
        hidden_goal_count=base.sample_count,
        distinct_visible_context_count=len(total_context_ids),
        distinct_session_count=len(session_ids),
    )


def _event_has_fallback_warning(warnings: List[str]) -> bool:
    return any("falling back" in warning.lower() for warning in warnings)


def _event_has_connection_refused(warnings: List[str]) -> bool:
    return any("connection refused" in warning.lower() for warning in warnings)


def write_scenario3_summary_json(
    output_path: str | Path,
    summary: ScenarioThreeSummary,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")


def write_scenario3_summary_markdown(
    output_path: str | Path,
    summary: ScenarioThreeSummary,
    dataset_path: str | Path,
    benign_dataset_path: str | Path,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 场景三：全局混排事件流评估",
        "",
        "攻击数据集：`%s`" % Path(dataset_path),
        "良性噪声池：`%s`" % Path(benign_dataset_path),
        "全局流 ID：`%s`" % summary.stream_id,
        "用户长期上下文：`%s`" % summary.user_context_id,
        "",
        "## 攻击链检测指标",
        "",
        "- 攻击样本数：%d" % summary.attack_sample_count,
        "- 防御成功数：%d" % summary.defended_count,
        "- 攻击穿透数：%d" % summary.bypass_count,
        "- 防御成功率：%.4f" % summary.defense_success_rate,
        "- 穿透率：%.4f" % summary.bypass_rate,
        "- 第 1 轮即熔断比例：%.4f" % summary.first_turn_stop_rate,
        "- 非首轮检测比例：%.4f" % summary.late_detection_rate,
        "- 平均触发熔断轮次：%.4f" % summary.average_stop_turn,
        "- 平均处理轮次数：%.4f" % summary.average_turns_processed,
        "- 平均子任务数：%.4f" % summary.average_task_count,
        "- 平均最终链路分数：%.4f" % summary.average_final_chain_score,
        "- assembly 驱动检测占比：%.4f" % summary.assembly_driven_detection_rate,
        "- bypass 中保留危险主题锚点的比例：%.4f" % summary.topic_anchored_bypass_rate,
        "- bypass 中主题丢失比例：%.4f" % summary.information_loss_bypass_rate,
        "",
        "## 全局流指标",
        "",
        "- 全局流总事件数：%d" % summary.stream_turn_count,
        "- 攻击事件数：%d" % summary.attack_turn_count,
        "- 良性背景事件数：%d" % summary.benign_turn_count,
        "- 良性背景误拒绝数：%d" % summary.benign_refusal_count,
        "- 良性背景误拒绝率：%.4f" % summary.benign_false_positive_rate,
        "- 攻击 turn warning 数：%d" % summary.attack_warning_turn_count,
        "- 攻击 turn warning 比例：%.4f" % summary.attack_warning_turn_rate,
        "- 良性 turn warning 数：%d" % summary.benign_warning_turn_count,
        "- 良性 turn warning 比例：%.4f" % summary.benign_warning_turn_rate,
        "- 攻击 turn fallback 数：%d" % summary.attack_fallback_turn_count,
        "- 攻击 turn fallback 比例：%.4f" % summary.attack_fallback_turn_rate,
        "- 良性 turn fallback 数：%d" % summary.benign_fallback_turn_count,
        "- 良性 turn fallback 比例：%.4f" % summary.benign_fallback_turn_rate,
        "- 攻击 turn Connection refused 数：%d" % summary.attack_connection_refused_turn_count,
        "- 良性 turn Connection refused 数：%d" % summary.benign_connection_refused_turn_count,
        "- 模型服务全程稳定：%s" % ("是" if summary.llm_runtime_stable else "否"),
        "- 隐藏攻击目标数量：%d" % summary.hidden_goal_count,
        "- 可见上下文数量：%d" % summary.distinct_visible_context_count,
        "- 全部 session 数量：%d" % summary.distinct_session_count,
        "",
        "## Bypass 分类",
        "",
    ]
    for item in summary.bypass_breakdown:
        lines.append("- %s：%d (%.4f)" % (item["category"], item["count"], item["rate"]))
    lines.extend(
        [
            "",
            "## 输出文件",
            "",
            "- `attack_results.json`：按隐藏攻击链汇总的检测结果",
            "- `attack_turn_log.csv`：按攻击链展开的攻击 turn 日志",
            "- `stream_events.json`：系统实际看到的单用户全局事件流 JSON",
            "- `stream_turn_log.csv`：系统实际看到的单用户全局事件流 CSV",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")

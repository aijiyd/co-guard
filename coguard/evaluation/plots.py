from __future__ import annotations

import html
import math
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from .metrics import SecurityEvaluationSummary, ThresholdPoint
from .runner import EvaluationRecord


PLOT_WIDTH = 900
PLOT_HEIGHT = 540


def write_all_plots(
    output_dir: str | Path,
    summary: SecurityEvaluationSummary,
    records: Sequence[EvaluationRecord],
) -> None:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "confusion_matrix.svg").write_text(
        render_confusion_matrix(summary),
        encoding="utf-8",
    )
    (directory / "metrics_overview.svg").write_text(
        render_metrics_overview(summary),
        encoding="utf-8",
    )
    (directory / "score_distribution.svg").write_text(
        render_score_distribution(records),
        encoding="utf-8",
    )
    (directory / "threshold_curves.svg").write_text(
        render_threshold_curves(summary.threshold_points),
        encoding="utf-8",
    )
    (directory / "adequacy_distribution.svg").write_text(
        render_adequacy_distribution(summary),
        encoding="utf-8",
    )


def render_confusion_matrix(summary: SecurityEvaluationSummary) -> str:
    maximum = max(
        1,
        summary.true_positive,
        summary.false_positive,
        summary.true_negative,
        summary.false_negative,
    )
    cells = [
        ("TP", summary.true_positive, 220, 150),
        ("FP", summary.false_positive, 460, 150),
        ("FN", summary.false_negative, 220, 320),
        ("TN", summary.true_negative, 460, 320),
    ]
    elements = [
        _title("Confusion Matrix"),
        _text(220, 120, "Predicted Harmful", size=18),
        _text(520, 120, "Predicted Benign", size=18),
        _text(120, 240, "True Harmful", size=18, rotate=-90),
        _text(120, 410, "True Benign", size=18, rotate=-90),
    ]
    for label, value, x, y in cells:
        intensity = value / float(maximum)
        fill = _heat_color(intensity)
        elements.append(_rect(x, y, 180, 120, fill=fill, rx=12))
        elements.append(_text(x + 90, y + 46, label, size=20, weight="bold"))
        elements.append(_text(x + 90, y + 80, str(value), size=28, weight="bold"))
    return _svg(elements)


def render_metrics_overview(summary: SecurityEvaluationSummary) -> str:
    metrics = [
        ("Accuracy", summary.accuracy),
        ("Precision", summary.precision),
        ("Recall", summary.recall),
        ("Specificity", summary.specificity),
        ("F1", summary.f1),
        ("Balanced", summary.balanced_accuracy),
    ]
    chart_left = 90
    chart_bottom = 430
    chart_height = 280
    bar_width = 90
    gap = 35
    elements = [
        _title("Core Metrics Overview"),
        _axis(chart_left, 120, chart_left, chart_bottom),
        _axis(chart_left, chart_bottom, 820, chart_bottom),
    ]
    for step in range(6):
        value = step / 5.0
        y = chart_bottom - chart_height * value
        elements.append(_grid_line(chart_left, y, 820, y))
        elements.append(_text(55, y + 5, "%.1f" % value, size=14))
    for index, (label, value) in enumerate(metrics):
        x = chart_left + 35 + index * (bar_width + gap)
        height = chart_height * value
        y = chart_bottom - height
        elements.append(_rect(x, y, bar_width, height, fill="#2C7FB8", rx=8))
        elements.append(_text(x + bar_width / 2, chart_bottom + 28, label, size=14))
        elements.append(_text(x + bar_width / 2, y - 10, "%.2f" % value, size=14))
    return _svg(elements)


def render_score_distribution(records: Sequence[EvaluationRecord], bins: int = 10) -> str:
    harmful = [record.score for record in records if record.true_label == 1]
    benign = [record.score for record in records if record.true_label == 0]
    minimum = min([0.0] + harmful + benign)
    maximum = max([1.0] + harmful + benign)
    if maximum == minimum:
        maximum = minimum + 1.0
    bin_edges = [
        minimum + (maximum - minimum) * index / float(bins)
        for index in range(bins + 1)
    ]
    harmful_counts = _histogram(harmful, bin_edges)
    benign_counts = _histogram(benign, bin_edges)
    peak = max([1] + harmful_counts + benign_counts)
    chart_left = 80
    chart_bottom = 430
    chart_top = 120
    chart_width = 760
    group_width = chart_width / float(bins)
    bar_width = group_width * 0.35
    chart_height = chart_bottom - chart_top

    elements = [
        _title("Score Distribution by Label"),
        _axis(chart_left, chart_top, chart_left, chart_bottom),
        _axis(chart_left, chart_bottom, 840, chart_bottom),
        _legend(670, 70, [("Harmful", "#D95F02"), ("Benign", "#1B9E77")]),
    ]
    for step in range(5):
        value = peak * step / 4.0
        y = chart_bottom - chart_height * (value / float(peak))
        elements.append(_grid_line(chart_left, y, 840, y))
        elements.append(_text(50, y + 5, str(int(round(value))), size=14))
    for index in range(bins):
        group_x = chart_left + index * group_width
        harmful_height = chart_height * (harmful_counts[index] / float(peak))
        benign_height = chart_height * (benign_counts[index] / float(peak))
        elements.append(
            _rect(
                group_x + group_width * 0.15,
                chart_bottom - harmful_height,
                bar_width,
                harmful_height,
                fill="#D95F02",
                rx=4,
            )
        )
        elements.append(
            _rect(
                group_x + group_width * 0.55,
                chart_bottom - benign_height,
                bar_width,
                benign_height,
                fill="#1B9E77",
                rx=4,
            )
        )
        label = "%.1f" % bin_edges[index]
        elements.append(_text(group_x + group_width / 2, chart_bottom + 26, label, size=12))
    return _svg(elements)


def render_threshold_curves(points: Sequence[ThresholdPoint]) -> str:
    if not points:
        return _svg([_title("Threshold Curves"), _text(450, 270, "No data", size=22)])

    minimum = min(point.threshold for point in points)
    maximum = max(point.threshold for point in points)
    if maximum == minimum:
        maximum = minimum + 1.0
    chart_left = 90
    chart_bottom = 430
    chart_top = 120
    chart_right = 830
    chart_width = chart_right - chart_left
    chart_height = chart_bottom - chart_top
    elements = [
        _title("Score Threshold Sweep"),
        _axis(chart_left, chart_top, chart_left, chart_bottom),
        _axis(chart_left, chart_bottom, chart_right, chart_bottom),
        _legend(630, 70, [("Precision", "#2C7FB8"), ("Recall", "#D95F02"), ("F1", "#31A354")]),
    ]
    for step in range(6):
        value = step / 5.0
        y = chart_bottom - chart_height * value
        elements.append(_grid_line(chart_left, y, chart_right, y))
        elements.append(_text(55, y + 5, "%.1f" % value, size=14))
    for step in range(5):
        ratio = step / 4.0
        x = chart_left + chart_width * ratio
        threshold = minimum + (maximum - minimum) * ratio
        elements.append(_grid_line(x, chart_top, x, chart_bottom, color="#F2F2F2"))
        elements.append(_text(x, chart_bottom + 24, "%.1f" % threshold, size=12))
    elements.append(_polyline(_line_points(points, minimum, maximum, "precision"), "#2C7FB8"))
    elements.append(_polyline(_line_points(points, minimum, maximum, "recall"), "#D95F02"))
    elements.append(_polyline(_line_points(points, minimum, maximum, "f1"), "#31A354"))
    return _svg(elements)


def render_adequacy_distribution(summary: SecurityEvaluationSummary) -> str:
    items = list(sorted(summary.adequacy_counts.items()))
    peak = max([1] + [count for _, count in items])
    chart_left = 90
    chart_bottom = 430
    chart_height = 280
    bar_width = 120
    gap = 55
    elements = [
        _title("Adequacy Distribution"),
        _axis(chart_left, 120, chart_left, chart_bottom),
        _axis(chart_left, chart_bottom, 830, chart_bottom),
    ]
    for step in range(5):
        value = peak * step / 4.0
        y = chart_bottom - chart_height * (value / float(peak))
        elements.append(_grid_line(chart_left, y, 830, y))
        elements.append(_text(55, y + 5, str(int(round(value))), size=14))
    for index, (label, count) in enumerate(items):
        x = chart_left + 35 + index * (bar_width + gap)
        height = chart_height * (count / float(peak))
        y = chart_bottom - height
        elements.append(_rect(x, y, bar_width, height, fill="#756BB1", rx=8))
        elements.append(_text(x + bar_width / 2, y - 10, str(count), size=14))
        elements.append(_text(x + bar_width / 2, chart_bottom + 28, label, size=13))
    return _svg(elements)


def _histogram(values: Sequence[float], bin_edges: Sequence[float]) -> List[int]:
    counts = [0 for _ in range(len(bin_edges) - 1)]
    for value in values:
        for index in range(len(bin_edges) - 1):
            left = bin_edges[index]
            right = bin_edges[index + 1]
            is_last = index == len(bin_edges) - 2
            if left <= value < right or (is_last and value == right):
                counts[index] += 1
                break
    return counts


def _line_points(
    points: Sequence[ThresholdPoint],
    minimum: float,
    maximum: float,
    field_name: str,
) -> str:
    chart_left = 90
    chart_bottom = 430
    chart_top = 120
    chart_right = 830
    chart_width = chart_right - chart_left
    chart_height = chart_bottom - chart_top
    coordinates = []
    for point in points:
        ratio = 0.0 if maximum == minimum else (point.threshold - minimum) / float(maximum - minimum)
        x = chart_left + chart_width * ratio
        y = chart_bottom - chart_height * getattr(point, field_name)
        coordinates.append("%.2f,%.2f" % (x, y))
    return " ".join(coordinates)


def _svg(elements: Iterable[str]) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">'
        '<rect x="0" y="0" width="%d" height="%d" fill="#FFFFFF"/>%s</svg>'
        % (
            PLOT_WIDTH,
            PLOT_HEIGHT,
            PLOT_WIDTH,
            PLOT_HEIGHT,
            PLOT_WIDTH,
            PLOT_HEIGHT,
            "".join(elements),
        )
    )


def _title(text: str) -> str:
    return _text(PLOT_WIDTH / 2, 42, text, size=26, weight="bold")


def _text(
    x: float,
    y: float,
    text: str,
    size: int = 16,
    weight: str = "normal",
    rotate: int | None = None,
) -> str:
    attrs = 'x="%.2f" y="%.2f" font-size="%d" font-family="Helvetica, Arial, sans-serif" font-weight="%s" text-anchor="middle" fill="#222222"' % (
        x,
        y,
        size,
        weight,
    )
    if rotate is not None:
        attrs += ' transform="rotate(%d %.2f %.2f)"' % (rotate, x, y)
    return "<text %s>%s</text>" % (attrs, html.escape(text))


def _rect(x: float, y: float, width: float, height: float, fill: str, rx: int = 0) -> str:
    safe_height = max(0.0, height)
    return (
        '<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s" rx="%d" ry="%d" stroke="#444444" stroke-width="1"/>'
        % (x, y, width, safe_height, fill, rx, rx)
    )


def _axis(x1: float, y1: float, x2: float, y2: float) -> str:
    return '<line x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" stroke="#444444" stroke-width="2"/>' % (
        x1,
        y1,
        x2,
        y2,
    )


def _grid_line(x1: float, y1: float, x2: float, y2: float, color: str = "#E6E6E6") -> str:
    return '<line x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" stroke="%s" stroke-width="1"/>' % (
        x1,
        y1,
        x2,
        y2,
        color,
    )


def _legend(x: float, y: float, items: Sequence[tuple[str, str]]) -> str:
    elements = []
    current_y = y
    for label, color in items:
        elements.append(_rect(x, current_y - 12, 18, 18, fill=color, rx=3))
        elements.append(
            '<text x="%.2f" y="%.2f" font-size="14" font-family="Helvetica, Arial, sans-serif" fill="#222222">%s</text>'
            % (x + 28, current_y + 2, html.escape(label))
        )
        current_y += 26
    return "".join(elements)


def _polyline(points: str, color: str) -> str:
    return '<polyline fill="none" stroke="%s" stroke-width="3" points="%s"/>' % (
        color,
        points,
    )


def _heat_color(intensity: float) -> str:
    clamped = max(0.0, min(1.0, intensity))
    red = int(255 - 40 * clamped)
    green = int(250 - 120 * clamped)
    blue = int(245 - 160 * clamped)
    return "#%02X%02X%02X" % (red, green, blue)

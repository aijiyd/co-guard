from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.font_manager as fm
import matplotlib.pyplot as plt
import numpy as np


def _find_chinese_font() -> fm.FontProperties | None:
    candidates = [
        "/System/Library/Fonts/Supplemental/Songti.ttc",
        "/System/Library/Fonts/Supplemental/SimSun.ttf",
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/Library/Fonts/Arial Unicode.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return fm.FontProperties(fname=path)
    return None


def main() -> None:
    font = _find_chinese_font()
    if font:
        plt.rcParams["font.family"] = font.get_name()
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["svg.fonttype"] = "none"

    strategies = ["rules", "llm", "hybrid"]
    metrics = {
        "拦截率": [100.00, 97.00, 98.00],
        "穿透率": [0.00, 3.00, 2.00],
        "误拒率": [46.43, 46.67, 44.83],
        "上下文组装驱动检测占比": [80.00, 85.57, 78.57],
    }
    colors = {
        "拦截率": "#2E86AB",
        "穿透率": "#F18F01",
        "误拒率": "#95C623",
        "上下文组装驱动检测占比": "#A23B72",
    }

    x = np.arange(len(strategies))
    width = 0.18
    offsets = np.array([-1.5, -0.5, 0.5, 1.5]) * width

    fig, ax = plt.subplots(figsize=(10, 6.4))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    for offset, (name, values) in zip(offsets, metrics.items()):
        bars = ax.bar(
            x + offset,
            values,
            width,
            label=name,
            color=colors[name],
            edgecolor="white",
            linewidth=0.8,
        )
        for bar, value in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                value + 1.1,
                f"{value:.2f}%",
                ha="center",
                va="bottom",
                fontsize=10,
                fontproperties=font,
            )

    ax.set_title(
        "图 1  三种裁决策略关键指标对比",
        fontsize=22,
        pad=18,
        fontproperties=font,
    )
    ax.set_xlabel("推理策略", fontsize=16, fontproperties=font)
    ax.set_ylabel("比例", fontsize=16, fontproperties=font)
    ax.set_xticks(x)
    ax.set_xticklabels(strategies, fontsize=13)
    ax.set_ylim(0, 110)
    ax.set_yticks(np.arange(0, 101, 20))
    ax.set_yticklabels([f"{value}%" for value in range(0, 101, 20)], fontsize=12)
    ax.grid(axis="y", linestyle="--", linewidth=0.9, alpha=0.42)
    ax.set_axisbelow(True)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_linewidth(1.0)
    ax.spines["bottom"].set_linewidth(1.0)

    legend = ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.13),
        ncol=4,
        frameon=True,
        fontsize=11,
        prop=font,
        borderpad=0.9,
        columnspacing=1.4,
        handlelength=2.2,
    )
    legend.get_frame().set_edgecolor("#666666")
    legend.get_frame().set_linewidth(0.8)
    legend.get_frame().set_facecolor("white")

    output_dir = Path("outputs/figures")
    output_dir.mkdir(parents=True, exist_ok=True)
    png_path = output_dir / "strategy_metrics_no_fallback.png"
    svg_path = output_dir / "strategy_metrics_no_fallback.svg"
    fig.tight_layout(rect=[0.02, 0.07, 0.98, 0.98])
    fig.savefig(png_path, dpi=450, bbox_inches="tight")
    fig.savefig(svg_path, bbox_inches="tight")
    plt.close(fig)
    print(png_path)
    print(svg_path)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Render compact charts from a ``summarize.py`` benchmark result.

The chart uses every workflow attempt in the summary.  A workflow that has a
mix of successful and failed rounds remains visible as ``partial`` so a fast
failure cannot be mistaken for a fast analysis.  Missing sampled metrics are
shown as empty bars instead of being treated as zero.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


STATUS_COLORS = {
    "complete": "#2468a2",
    "partial": "#b7791f",
    "failed": "#b83232",
}


def load_summary(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    workflows = value.get("workflows")
    if not isinstance(workflows, list) or not all(isinstance(item, dict) for item in workflows):
        raise ValueError(f"summary has no usable workflows array: {path}")
    return value


def metric_value(workflow: dict[str, Any], name: str) -> tuple[float | None, float | None, float | None]:
    stats = workflow.get(name)
    if not isinstance(stats, dict):
        return None, None, None
    median = stats.get("median")
    minimum = stats.get("minimum")
    maximum = stats.get("maximum")
    values = [value if isinstance(value, (int, float)) else None for value in (median, minimum, maximum)]
    return tuple(float(value) if value is not None else None for value in values)  # type: ignore[return-value]


def workflow_status(workflow: dict[str, Any]) -> str:
    samples = workflow.get("samples")
    successes = workflow.get("successes")
    if isinstance(samples, int) and isinstance(successes, int) and samples > 0:
        if successes == samples:
            return "complete"
        if successes == 0:
            return "failed"
    return "partial"


def display_name(workflow: dict[str, Any]) -> str:
    name = workflow.get("workflow")
    return str(name) if name else "unknown"


def annotation_text(workflow: dict[str, Any], metric: str) -> str:
    median, minimum, maximum = metric_value(workflow, metric)
    if median is None:
        return "n/a"
    if metric == "wall_ms" and minimum is not None and maximum is not None:
        return f"{median / 1000:.2f}s [{minimum / 1000:.2f}–{maximum / 1000:.2f}]"
    if metric == "sampled_family_cpu_ms":
        return f"{median / 1000:.2f}s"
    return f"{median:.0f} MiB"


def output_paths(value: Path) -> tuple[Path, Path]:
    if value.suffix.lower() in {".png", ".svg"}:
        stem = value.with_suffix("")
    else:
        stem = value
    return stem.with_suffix(".png"), stem.with_suffix(".svg")


def strip_svg_line_end_whitespace(path: Path) -> None:
    """Remove generator whitespace without changing SVG tokens or newlines."""
    original = path.read_text()
    normalized_lines: list[str] = []
    for line in original.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        newline = line[len(content) :]
        normalized_lines.append(content.rstrip(" \t") + newline)
    normalized = "".join(normalized_lines)
    if normalized != original:
        path.write_text(normalized)


def render(summary: dict[str, Any], output: Path) -> tuple[Path, Path]:
    # Import only when rendering so summary inspection and --help do not load
    # the plotting stack.
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    workflows = [item for item in summary["workflows"] if isinstance(item, dict)]
    if not workflows:
        raise ValueError("summary contains no workflows to plot")

    labels = [display_name(item) for item in workflows]
    positions = list(range(len(workflows)))
    colors = [STATUS_COLORS[workflow_status(item)] for item in workflows]
    metrics = (
        ("wall_ms", "Wall time (seconds)", "wall time"),
        ("sampled_family_cpu_ms", "Sampled process-family CPU (seconds)", "sampled CPU"),
        ("sampled_family_peak_rss_mib", "Sampled peak process-family RSS (MiB)", "peak RSS"),
    )

    figure_height = max(7.5, 0.38 * len(workflows) + 2.5)
    figure, axes = plt.subplots(1, 3, figsize=(19, figure_height), sharey=True, constrained_layout=False)
    figure.subplots_adjust(left=0.25, right=0.98, top=0.90, bottom=0.16, wspace=0.32)

    for axis, (metric, title, _) in zip(axes, metrics):
        coordinate_scale = 0.001 if metric in {"wall_ms", "sampled_family_cpu_ms"} else 1.0
        medians: list[float] = []
        lower_errors: list[float] = []
        upper_errors: list[float] = []
        for workflow in workflows:
            median, minimum, maximum = metric_value(workflow, metric)
            if median is None:
                medians.append(0.0)
                lower_errors.append(0.0)
                upper_errors.append(0.0)
                continue
            medians.append(median * coordinate_scale)
            lower_errors.append(max(0.0, (median - minimum) * coordinate_scale) if minimum is not None else 0.0)
            upper_errors.append(max(0.0, (maximum - median) * coordinate_scale) if maximum is not None else 0.0)
        bars = axis.barh(
            positions,
            medians,
            xerr=[lower_errors, upper_errors],
            error_kw={"ecolor": "#263238", "elinewidth": 0.8, "capsize": 2.5},
            color=colors,
            alpha=0.88,
            height=0.68,
        )
        axis.set_title(title, fontsize=10, pad=10)
        axis.grid(axis="x", color="#d9dee5", linewidth=0.7, alpha=0.8)
        axis.set_axisbelow(True)
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)
        axis.tick_params(axis="y", length=0)
        axis.tick_params(axis="x", labelsize=8)

        maximum = max((median + error for median, error in zip(medians, upper_errors)), default=0.0)
        # Reserve room for the complete wall-time range labels.  This is
        # deliberately generous because long labels are more useful than a
        # tightly packed axis in a static report figure.
        padding = maximum * 0.60 if maximum else 1.0
        axis.set_xlim(0, maximum + padding)
        for bar, workflow, median in zip(bars, workflows, medians):
            annotation = annotation_text(workflow, metric)
            if median > 0:
                axis.text(
                    bar.get_width() + padding * 0.04,
                    bar.get_y() + bar.get_height() / 2,
                    annotation,
                    va="center",
                    ha="left",
                    fontsize=7.5,
                    color="#263238",
                )
            else:
                axis.text(padding * 0.04, bar.get_y() + bar.get_height() / 2, annotation, va="center", fontsize=7.5, color="#59636e")

    axes[0].set_yticks(positions, labels, fontsize=8)
    axes[0].invert_yaxis()
    figure.suptitle(
        "REA native MCP benchmark — all workflow attempts",
        fontsize=14,
        fontweight="bold",
        x=0.25,
        ha="left",
    )
    figure.text(
        0.25,
        0.935,
        "Bars show workflow medians; wall-time labels include the observed minimum–maximum range."
        " Sampled CPU/RSS are lower bounds.",
        fontsize=9,
        color="#59636e",
        ha="left",
    )
    legend = [Patch(facecolor=color, label=label) for label, color in STATUS_COLORS.items()]
    figure.legend(handles=legend, loc="lower center", bbox_to_anchor=(0.72, 0.025), ncol=3, frameon=False, fontsize=9)

    png_path, svg_path = output_paths(output)
    png_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(png_path, dpi=180, facecolor="white")
    figure.savefig(svg_path, facecolor="white")
    strip_svg_line_end_whitespace(svg_path)
    plt.close(figure)
    return png_path, svg_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True, type=Path, help="summary.json produced by summarize.py")
    parser.add_argument("--output", required=True, type=Path, help="output path or filename stem; writes PNG and SVG")
    args = parser.parse_args()
    png_path, svg_path = render(load_summary(args.summary), args.output)
    print(f"wrote {png_path}")
    print(f"wrote {svg_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

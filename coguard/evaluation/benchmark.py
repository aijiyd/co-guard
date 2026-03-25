from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence


DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


@dataclass(frozen=True)
class BenchmarkSample:
    """One labeled evaluation sample fed into the defense pipeline."""

    sample_id: str
    query: str
    label: int
    source: str
    category: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)


def load_csv_samples(
    path: str | Path,
    text_column: str,
    label: int,
    source: str | None = None,
    limit: int | None = None,
    category_column: str | None = None,
    metadata_columns: Sequence[str] | None = None,
) -> List[BenchmarkSample]:
    """Load labeled samples from a CSV file."""

    csv_path = Path(path)
    resolved_source = source or csv_path.stem
    extras = list(metadata_columns or [])
    samples: List[BenchmarkSample] = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader, start=1):
            text = (row.get(text_column) or "").strip()
            if not text:
                continue
            category = (row.get(category_column) or "").strip() if category_column else ""
            metadata = {key: row.get(key, "") for key in extras if key in row}
            samples.append(
                BenchmarkSample(
                    sample_id="%s-%04d" % (resolved_source, index),
                    query=text,
                    label=label,
                    source=resolved_source,
                    category=category,
                    metadata=metadata,
                )
            )
            if limit is not None and len(samples) >= limit:
                break
    return samples


def load_default_benchmark(
    data_dir: str | Path | None = None,
    harmful_limit: int | None = None,
    benign_limit: int | None = None,
    include_harmful_strings: bool = False,
    harmful_strings_limit: int | None = None,
) -> List[BenchmarkSample]:
    """Load the built-in benchmark bundle used by the evaluation CLI."""

    root = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
    samples = []
    samples.extend(
        load_csv_samples(
            root / "harmful_behaviors.csv",
            text_column="goal",
            label=1,
            source="harmful_behaviors",
            limit=harmful_limit,
        )
    )
    samples.extend(
        load_csv_samples(
            root / "benign_behaviors.csv",
            text_column="goal",
            label=0,
            source="benign_behaviors",
            limit=benign_limit,
            category_column="category",
        )
    )
    if include_harmful_strings:
        samples.extend(
            load_csv_samples(
                root / "harmful_strings.csv",
                text_column="target",
                label=1,
                source="harmful_strings",
                limit=harmful_strings_limit,
            )
        )
    return samples


def count_by_label(samples: Iterable[BenchmarkSample]) -> Dict[str, int]:
    counts = {"harmful": 0, "benign": 0}
    for sample in samples:
        counts["harmful" if sample.label else "benign"] += 1
    return counts

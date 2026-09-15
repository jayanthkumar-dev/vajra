"""Offline ML experiment over approved scalar features.

This module is an experiment harness, not a replacement for deterministic detectors.
"""

import argparse
import json
import time
from pathlib import Path

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from vajra.ml.dataset import (
    FEATURE_NAMES,
    generate_synthetic_dataset,
    load_dataset,
    save_dataset,
)


def run_experiment(
    dataset_path: str | Path,
    model_path: str | Path,
    metrics_path: str | Path,
    *,
    sample_count: int = 240,
    seed: int = 42,
) -> dict[str, object]:
    """Train, evaluate, and persist a reproducible offline experiment."""
    dataset_file = Path(dataset_path)
    provenance_file = dataset_file.with_suffix(dataset_file.suffix + ".meta.json")
    if dataset_file.exists():
        rows = load_dataset(dataset_file)
        provenance = _load_provenance(provenance_file)
        dataset_source = provenance.get("dataset_source", "provided_csv")
    else:
        rows = generate_synthetic_dataset(sample_count=sample_count, seed=seed)
        dataset_file.parent.mkdir(parents=True, exist_ok=True)
        save_dataset(rows, dataset_file)
        dataset_source = "generated_synthetic_lab_csv"
        provenance_file.write_text(
            json.dumps({"dataset_source": dataset_source, "seed": seed}, indent=2),
            encoding="utf-8",
        )

    x = [[row.values[name] for name in FEATURE_NAMES] for row in rows]
    y = [row.label for row in rows]
    x_train, x_temp, y_train, y_temp = train_test_split(
        x,
        y,
        test_size=0.4,
        random_state=seed,
        stratify=y,
    )
    x_validation, x_test, y_validation, y_test = train_test_split(
        x_temp,
        y_temp,
        test_size=0.5,
        random_state=seed,
        stratify=y_temp,
    )

    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "classifier",
                LogisticRegression(max_iter=1000, random_state=seed, solver="liblinear"),
            ),
        ]
    )
    pipeline.fit(x_train, y_train)
    validation_metrics = _classification_metrics(pipeline.predict(x_validation), y_validation)
    start = time.perf_counter_ns()
    test_predictions = pipeline.predict(x_test)
    elapsed_seconds = (time.perf_counter_ns() - start) / 1_000_000_000
    test_metrics = _classification_metrics(test_predictions, y_test)
    test_metrics["inference_total_seconds"] = elapsed_seconds
    test_metrics["inference_seconds_per_sample"] = elapsed_seconds / len(x_test)
    test_metrics["inference_sample_count"] = len(x_test)

    artifact = {
        "pipeline": pipeline,
        "feature_names": FEATURE_NAMES,
        "label_meaning": {0: "benign", 1: "abnormal"},
        "seed": seed,
        "model_type": "StandardScaler + LogisticRegression",
        "dataset_source": dataset_source,
        "cpu_only": True,
    }
    model_file = Path(model_path)
    metrics_file = Path(metrics_path)
    model_file.parent.mkdir(parents=True, exist_ok=True)
    metrics_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, model_file)

    metrics = {
        "dataset_source": dataset_source,
        "synthetic_dataset": dataset_source == "generated_synthetic_lab_csv",
        "seed": seed,
        "feature_names": list(FEATURE_NAMES),
        "split_counts": {
            "train": len(x_train),
            "validation": len(x_validation),
            "test": len(x_test),
        },
        "validation": validation_metrics,
        "test": test_metrics,
        "model_artifact": str(model_file),
        "preprocessing_fit_on": "train_only",
        "ml_role": "complements deterministic and statistical detectors",
    }
    metrics_file.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def _load_provenance(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def _classification_metrics(predictions, labels) -> dict[str, object]:
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    return {
        "precision": precision_score(labels, predictions, zero_division=0),
        "recall": recall_score(labels, predictions, zero_division=0),
        "f1": f1_score(labels, predictions, zero_division=0),
        "confusion_matrix": matrix.tolist(),
    }


def main() -> None:
    """Run the offline experiment from the command line."""
    parser = argparse.ArgumentParser(description="Run the offline VAJRA ML experiment")
    parser.add_argument("--dataset", default="artifacts/synthetic_features.csv")
    parser.add_argument("--model", default="artifacts/vajra_logistic_regression.joblib")
    parser.add_argument("--metrics", default="artifacts/ml_metrics.json")
    parser.add_argument("--samples", type=int, default=240)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    metrics = run_experiment(
        args.dataset,
        args.model,
        args.metrics,
        sample_count=args.samples,
        seed=args.seed,
    )
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
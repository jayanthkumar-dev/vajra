import json

import joblib

from vajra.ml.dataset import FEATURE_NAMES, generate_synthetic_dataset, load_dataset, save_dataset
from vajra.ml.experiment import run_experiment


def test_synthetic_dataset_is_reproducible_and_labeled(tmp_path):
    first = generate_synthetic_dataset(sample_count=20, seed=7)
    second = generate_synthetic_dataset(sample_count=20, seed=7)

    assert first == second
    assert {row.label for row in first} == {0, 1}
    path = tmp_path / "dataset.csv"
    save_dataset(first, path)
    assert load_dataset(path) == first


def test_experiment_separates_data_fits_train_only_and_saves_artifacts(tmp_path):
    metrics = run_experiment(
        tmp_path / "dataset.csv",
        tmp_path / "model.joblib",
        tmp_path / "metrics.json",
        sample_count=40,
        seed=11,
    )

    assert metrics["feature_names"] == list(FEATURE_NAMES)
    assert metrics["split_counts"] == {"train": 24, "validation": 8, "test": 8}
    assert metrics["preprocessing_fit_on"] == "train_only"
    assert metrics["synthetic_dataset"] is True
    assert (tmp_path / "model.joblib").exists()
    artifact = joblib.load(tmp_path / "model.joblib")
    assert artifact["feature_names"] == FEATURE_NAMES
    assert artifact["cpu_only"] is True
    assert len(artifact["pipeline"].predict([[1.0] * len(FEATURE_NAMES)])) == 1
    saved_metrics = json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8"))
    test_metrics = saved_metrics["test"]
    assert 0 <= test_metrics["precision"] <= 1
    assert 0 <= test_metrics["recall"] <= 1
    assert 0 <= test_metrics["f1"] <= 1
    assert len(test_metrics["confusion_matrix"]) == 2
    assert test_metrics["inference_total_seconds"] >= 0
    assert test_metrics["inference_seconds_per_sample"] >= 0
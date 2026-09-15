# Offline ML Experiment

The ML layer is an experiment that complements, and does not replace, the deterministic and statistical detectors. It uses a CPU-only `StandardScaler` plus `LogisticRegression` pipeline over the approved scalar `FeatureResult` keys in `vajra.ml.dataset.FEATURE_NAMES`.

## Run

```powershell
python -m vajra.ml.experiment --dataset artifacts/synthetic_features.csv --model artifacts/vajra_logistic_regression.joblib --metrics artifacts/ml_metrics.json --samples 240 --seed 42
```

When the dataset path does not exist, the command creates a reproducible synthetic/lab CSV with explicit labels: `0` means benign and `1` means abnormal. It then creates deterministic train, validation, and test partitions using the supplied seed, fits preprocessing and the classifier on the training partition only, writes the joblib model artifact, and writes measured metrics as JSON.

The generated dataset is synthetic and its labels are controlled lab labels, not real-world ground truth. Metrics from it must not be described as production accuracy or generalization performance. The experiment does not claim accuracy beyond the measured validation and test outputs, and it does not inspect payloads, decrypt traffic, or contact a network.

The test metrics include precision, recall, F1, a `[benign, abnormal]` confusion matrix, total test inference time, and mean test inference time per sample. The timing is a measurement of the local offline run and is not a system benchmark.
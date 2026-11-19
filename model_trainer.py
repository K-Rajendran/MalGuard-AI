"""Reproducible training on authentic repository data; never run during app startup."""
import json
import platform
from datetime import datetime, timezone
from time import perf_counter
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             confusion_matrix, roc_auc_score, average_precision_score)
from malguard.core import ROOT, sha256


def metrics(y, pred, score):
    tn, fp, fn, tp = confusion_matrix(y == 0, pred == 0, labels=[False, True]).ravel()
    return {'accuracy': float(accuracy_score(y, pred)), 'malware_precision': float(precision_score(y, pred, pos_label=0)),
            'malware_recall': float(recall_score(y, pred, pos_label=0)), 'malware_f1': float(f1_score(y, pred, pos_label=0)),
            'false_positive_rate': float(fp / (tn + fp)), 'false_negative_rate': float(fn / (fn + tp)),
            'roc_auc': float(roc_auc_score(y == 0, score)), 'pr_auc_average_precision': float(average_precision_score(y == 0, score)),
            'confusion_matrix_benign_malware': [[int(tn), int(fp)], [int(fn), int(tp)]]}


def train():
    source = ROOT / 'datasets/dataset_1.csv'
    data = pd.read_csv(source)
    columns = [c for c in data if c not in ('ID', 'md5', 'legitimate', 'VersionInformationSize')]
    # VersionInformationSize excluded: legacy parser returned zero for nested FileInfo.
    original = len(data)
    numeric = data[columns].apply(pd.to_numeric, errors='coerce')
    valid = np.isfinite(numeric).all(axis=1) & (numeric >= 0).all(axis=1) & data.legitimate.isin([0, 1])
    data = data.loc[valid].copy()
    signatures = pd.util.hash_pandas_object(data[columns].round(8), index=False)
    data['_signature'] = signatures
    bad_signatures = data.groupby('_signature').legitimate.nunique()
    bad_hashes = data.groupby('md5').legitimate.nunique()
    data = data[~data._signature.isin(bad_signatures[bad_signatures > 1].index)]
    data = data[~data.md5.isin(bad_hashes[bad_hashes > 1].index)]
    data = data.drop_duplicates('md5').drop_duplicates('_signature')
    x, y = data[columns].to_numpy(), data.legitimate.to_numpy()
    ids = np.arange(len(data))
    train_ids, test_ids = train_test_split(ids, test_size=.2, random_state=42, stratify=y)
    train_ids, val_ids = train_test_split(train_ids, test_size=.25, random_state=43, stratify=y[train_ids])
    candidates = {
        'RandomForest': RandomForestClassifier(n_estimators=128, min_samples_leaf=2, class_weight='balanced', random_state=42, n_jobs=2),
        'LogisticRegression': make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)),
    }
    comparison = {}
    for name, model in candidates.items():
        model.fit(x[train_ids], y[train_ids])
        comparison[name] = float(f1_score(y[val_ids], model.predict(x[val_ids]), pos_label=0))
        print(name, 'validation malware F1', comparison[name], flush=True)
    winner = max(comparison, key=comparison.get)
    model = candidates[winner]
    # Test remains untouched during candidate selection; preserve train-only fitted model.
    started = perf_counter()
    pred = model.predict(x[test_ids])
    elapsed = perf_counter() - started
    score = model.predict_proba(x[test_ids])[:, list(model.classes_).index(0)]
    results = metrics(y[test_ids], pred, score)
    artifact = ROOT / 'model/malguard.joblib'
    joblib.dump(model, artifact, compress=3)
    manifest = {'schema_version': 1, 'algorithm': winner, 'features': columns, 'labels': {'0': 'Malware', '1': 'Legitimate'},
        'artifact_sha256': sha256(artifact.read_bytes()), 'artifact_bytes': artifact.stat().st_size,
        'dataset_sha256': sha256(source.read_bytes()), 'dataset': 'datasets/dataset_1.csv',
        'original_rows': original, 'retained_rows': len(data), 'removed_rows': original-len(data),
        'train_rows': len(train_ids), 'validation_rows': len(val_ids), 'test_rows': len(test_ids),
        'split_seed': [42, 43], 'validation_malware_f1': comparison, 'test_metrics': results,
        'test_inference_ms_per_row_batch': elapsed * 1000 / len(test_ids),
        'sklearn': sklearn.__version__, 'python': platform.python_version(),
        'trained_at_utc': datetime.now(timezone.utc).isoformat(), 'calibrated': False,
        'limitations': 'Deduplicated hash/rounded feature rows; no family or temporal labels, so family leakage and modern real-world generalization are unverified.',
        'test_partition_sha256': sha256('\n'.join(sorted(data.iloc[test_ids].md5)).encode()),
        'split_overlap_hashes': len(set(data.iloc[train_ids].md5) & set(data.iloc[test_ids].md5)),
        'test_examples': [{'features': dict(zip(columns, map(float, x[i]))), 'label': int(y[i])} for i in [next(j for j in test_ids if y[j] == c and int(model.predict(x[j:j+1])[0]) == c) for c in (0,1)]]}
    (ROOT / 'model/manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({k:v for k,v in manifest.items() if k not in ('test_examples','features')}, indent=2))


if __name__ == '__main__':
    train()

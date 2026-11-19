"""Trusted artifact loading and a single feature-ordered prediction path."""
from functools import lru_cache
import json
import warnings
import joblib
import numpy as np
from sklearn.exceptions import InconsistentVersionWarning
from .core import ROOT, AnalysisError, sha256


@lru_cache(maxsize=1)
def load_model():
    try:
        manifest = json.loads((ROOT / 'model/manifest.json').read_text())
        artifact = ROOT / 'model/malguard.joblib'
        if sha256(artifact.read_bytes()) != manifest['artifact_sha256']:
            raise AnalysisError('Model integrity check failed. Restore the packaged model.')
        with warnings.catch_warnings():
            warnings.simplefilter('error', InconsistentVersionWarning)
            model = joblib.load(artifact)
        if list(model.classes_) != [0, 1] or model.n_features_in_ != len(manifest['features']):
            raise AnalysisError('Model schema or labels do not match its manifest.')
        # Parallel tree accumulation can change the final floating-point bit.
        # Serial inference keeps repeated sensitivity reports deterministic and
        # avoids nested worker pools for these small, single-file predictions.
        if hasattr(model, 'n_jobs'):
            model.n_jobs = 1
        return model, manifest
    except AnalysisError:
        raise
    except Exception:
        raise AnalysisError('Model unavailable or incompatible. Validate dependencies and run the documented training command.') from None


def predict(features: dict) -> dict:
    model, manifest = load_model()
    try:
        vector = np.asarray([[features[key] for key in manifest['features']]], dtype=float)
    except (KeyError, TypeError, ValueError):
        raise AnalysisError('Extracted features do not match the trained schema.') from None
    if not np.isfinite(vector).all() or (vector < 0).any():
        raise AnalysisError('Model features must be finite nonnegative values.')
    label = int(model.predict(vector)[0])
    score = float(model.predict_proba(vector)[0, list(model.classes_).index(0)])
    confidence = score if label == 0 else 1 - score
    return {'label': label, 'verdict': 'Malware' if label == 0 else 'Legitimate',
            'malware_score': score, 'confidence': confidence, 'review': confidence < .8,
            'risk': 'High' if label == 0 else ('Review' if confidence < .8 else 'Low'),
            'model_version': manifest['artifact_sha256'][:12]}

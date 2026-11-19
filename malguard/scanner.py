"""Static-only upload analysis, isolated parsing and genuine model inference."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import subprocess
import sys
from time import perf_counter
from uuid import uuid4
from .core import ROOT, AnalysisError, safe_name, validate_bytes, sha256
from .ml import predict


def extract(data: bytes) -> dict:
    validate_bytes(data)
    if not data.startswith(b'MZ'):
        raise AnalysisError('Unsupported format. The model supports Windows PE executables and DLLs only; no verdict was produced.')
    try:
        process = subprocess.run([sys.executable, '-m', 'malguard.worker'], input=data, capture_output=True,
                                 cwd=ROOT, timeout=15, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if process.returncode:
            raise AnalysisError('Corrupt or unsupported PE structure; no verdict was produced.')
        return json.loads(process.stdout)
    except subprocess.TimeoutExpired:
        raise AnalysisError('Static parsing exceeded the 15-second limit. No verdict was produced.') from None


def entropy(data: bytes) -> float:
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in Counter(data).values()) if data else 0.0


def scan(data: bytes, filename: str, retain_name: bool = True) -> dict:
    start = perf_counter()
    features = extract(data)
    prediction = predict(features)
    observations = []
    value = entropy(data)
    if value > 7:
        observations.append('High whole-file entropy; compression/encryption can cause this in benign files too.')
    if features.get('ImportsNb', 0) == 0:
        observations.append('No imports parsed; this alone is not evidence of malicious behavior.')
    return {'scan_id': str(uuid4()), 'timestamp': datetime.now(timezone.utc).isoformat(),
            'sha256': sha256(data), 'md5': hashlib.md5(data, usedforsecurity=False).hexdigest(),
            'filename': safe_name(filename) if retain_name else 'withheld', 'size': len(data),
            'format': 'PE', 'entropy': value, 'features': features, **prediction,
            'observations': observations, 'status': 'completed',
            'duration_ms': round((perf_counter() - start) * 1000, 3),
            'score_interpretation': 'Uncalibrated model score, not a probability of real-world harm.',
            'follow_up': 'Quarantine and obtain independent analysis; do not execute.' if prediction['label'] == 0 else 'A legitimate prediction does not establish safety. Verify source and signatures independently.'}

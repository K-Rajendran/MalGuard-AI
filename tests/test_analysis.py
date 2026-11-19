import json
import pytest
from malguard.core import AnalysisError, MAX_UPLOAD, ROOT, safe_name, sha256
from malguard.scanner import extract, scan, entropy
from malguard.ml import load_model, predict
from malguard.resilience import evaluate, DIMENSIONS
from model_trainer import metrics
import numpy as np


@pytest.mark.parametrize('data',[b'',b'hello',b'%PDF-1.0',b'MZbroken',b'\x80\x04pickle'])
def test_invalid_files_never_legitimate(data):
    with pytest.raises(AnalysisError): scan(data,'../../bad.exe')


def test_limits():
    with pytest.raises(AnalysisError): extract(b'MZ'+b'\0'*MAX_UPLOAD)


def test_static_pipeline(inert_pe,record):
    model,manifest = load_model()
    assert record['sha256'] == sha256(inert_pe)
    assert record['format'] == 'PE'
    assert record['features']['Machine'] == 332
    assert record['features']['SectionsNb'] == 1
    assert record['features']['SectionMaxRawsize'] == 512
    assert set(manifest['features']) <= record['features'].keys()
    assert predict(record['features'])['label'] == record['label']
    assert record['duration_ms'] > 0
    assert safe_name('../../evil<script>.exe') == 'evil_script_.exe'
    assert entropy(bytes(range(256))) == 8


def test_target_model_and_labels():
    model,manifest = load_model()
    assert list(model.classes_) == [0,1]
    assert manifest['split_overlap_hashes'] == 0
    assert manifest['test_metrics']['accuracy'] > .9
    for example in manifest['test_examples']:
        result = predict(example['features'])
        assert result['label'] == example['label']
        assert result == predict(dict(reversed(list(example['features'].items()))))


def test_metric_positive_class():
    result = metrics(np.array([0,0,0,1]),np.array([0,1,1,1]),np.array([.9,.4,.3,.1]))
    assert result['malware_precision'] == 1
    assert result['malware_recall'] == pytest.approx(1/3)
    assert result['false_positive_rate'] == 0
    assert result['false_negative_rate'] == pytest.approx(2/3)
    assert result['confusion_matrix_benign_malware'] == [[1,0],[2,1]]


def test_resilience_real_inference(record):
    features = record['features'].copy()
    a = evaluate(features,list(DIMENSIONS[:2]),count=8)
    b = evaluate(features,list(DIMENSIONS[:2]),count=8)
    assert a == b and features == record['features']
    assert a['stable']+a['flips'] == 8
    assert a['stability_percent'] == 100*a['stable']/8
    assert all(row['before'] != row['after'] for row in a['scenarios'])


@pytest.mark.parametrize('count,strength,dimensions',[(0,.1,['CheckSum']),(129,.1,['CheckSum']),(4,1,['CheckSum']),(4,.1,['AddressOfEntryPoint']),(4,.1,[])])
def test_unsafe_scenarios_rejected(count,strength,dimensions):
    with pytest.raises(AnalysisError): evaluate({},dimensions,strength,count)

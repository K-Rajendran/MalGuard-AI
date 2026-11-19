"""Compatibility API for the original CLI; unsupported files raise an explicit error."""
from pathlib import Path
from malguard.scanner import scan, extract
from malguard.features import get_entropy
from malguard.core import MAX_UPLOAD


def _read(path):
    with Path(path).open('rb') as handle:
        return handle.read(MAX_UPLOAD + 1)


def extract_info(fpath):
    return extract(_read(fpath))


def checkFile(file):
    return scan(_read(file), Path(file).name)['label']

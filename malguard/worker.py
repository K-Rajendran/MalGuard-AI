"""Bounded parser worker: uploaded bytes are data, never code or a file path."""
import json
import sys
from .core import MAX_UPLOAD
from .features import extract_info


def main():
    data = sys.stdin.buffer.read(MAX_UPLOAD + 1)
    try:
        if not data.startswith(b'MZ') or len(data) > MAX_UPLOAD:
            raise ValueError('Unsupported file')
        features = extract_info(data)
        if not features:
            raise ValueError('Invalid PE')
        print(json.dumps(features, allow_nan=False))
    except Exception:
        sys.exit(2)


if __name__ == '__main__':
    main()

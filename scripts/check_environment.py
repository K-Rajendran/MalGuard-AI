"""Verify interpreter and runtime imports originate in this project environment."""
import importlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / '.venv'


def main():
    assert sys.version_info[:2] == (3, 15), 'CPython 3.15 is required for this validated environment.'
    assert Path(sys.prefix).resolve() == EXPECTED.resolve(), 'Use the project .venv interpreter.'
    print(sys.version)
    for name in ('streamlit','sklearn','numpy','scipy','pandas','pyarrow','joblib','cryptography','Crypto',
                 'pyAesCrypt','pefile','networkx','pyvis','plotly','ruamel.yaml','sqlalchemy','psycopg','authlib','joserfc'):
        module = importlib.import_module(name)
        path = Path(module.__file__).resolve()
        assert path.is_relative_to(EXPECTED.resolve()), f'{name} was imported from outside .venv'
        print(name, getattr(module,'__version__','imported'), path)


if __name__ == '__main__': main()

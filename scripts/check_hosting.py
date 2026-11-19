"""Read-only preflight; never provisions, deploys, or prints credentials."""
import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def main():
    from malguard.core import AnalysisError
    from malguard.settings import load_settings
    parser=argparse.ArgumentParser()
    parser.add_argument('--production',action='store_true',help='Require production secrets and a reachable PostgreSQL database.')
    args=parser.parse_args()
    try:
        config=tomllib.loads((ROOT/'.streamlit/config.toml').read_text())
        if config['global']['developmentMode']: raise AnalysisError('Disable Streamlit development mode.')
        manifest=json.loads((ROOT/'model/manifest.json').read_text())
        if hashlib.sha256((ROOT/'model/malguard.joblib').read_bytes()).hexdigest()!=manifest['artifact_sha256']:
            raise AnalysisError('Packaged model integrity check failed.')
        from malguard.ml import load_model
        load_model()
        from malguard.presentation import GUIDES, animation_html
        for _,asset in GUIDES.values(): animation_html(asset)
        print('Local preflight passed: release configuration, model, and animation assets.')
        if args.production:
            path=ROOT/'.streamlit/secrets.toml'
            secrets=tomllib.loads(path.read_text()) if path.exists() else {}
            settings=load_settings(secrets)
            if not settings.production: raise AnalysisError('Set MALGUARD_MODE=production and configure deployment secrets.')
            from sqlalchemy import create_engine,text
            engine=create_engine(settings.database_url,connect_args={'connect_timeout':10},pool_pre_ping=True)
            try:
                with engine.connect() as connection:
                    connection.execute(text('SELECT 1')).scalar_one()
            finally: engine.dispose()
            print('Production configuration and PostgreSQL connectivity passed. Complete the real provider sign-in and backup/restore checks before release.')
        else:
            print('Hosted PostgreSQL and provider sign-in were not checked. Use --production with your deployment configuration.')
    except AnalysisError as exc:
        print(str(exc),file=sys.stderr); return 1
    except Exception as exc:
        print(f'Preflight failed ({type(exc).__name__}); check dependencies and deployment configuration. Credentials are not displayed.',file=sys.stderr); return 1
    return 0

if __name__=='__main__': sys.exit(main())

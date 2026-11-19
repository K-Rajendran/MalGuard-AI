"""Owner-scoped SQL storage. SQLite locally, PostgreSQL by configured URL."""
from datetime import datetime, timedelta, timezone
import json
import math
import re
from uuid import UUID
from sqlalchemy import (create_engine, MetaData, Table, Column, String, Float, Integer, Text,
                        UniqueConstraint, Index, select, func, case, delete, event, text)
from sqlalchemy.exc import IntegrityError
from .core import AnalysisError, ROOT

metadata = MetaData()
schema = Table('malguard_schema', metadata, Column('version', Integer, primary_key=True))
scans = Table('scans_v1', metadata,
    Column('scan_id', String(36), primary_key=True), Column('owner', String(128), nullable=False),
    Column('timestamp', String(40), nullable=False), Column('sha256', String(64), nullable=False),
    Column('filename', String(120), nullable=False), Column('format', String(20), nullable=False),
    Column('verdict', String(20), nullable=False), Column('risk', String(20), nullable=False),
    Column('model_version', String(64), nullable=False), Column('review', Integer, nullable=False),
    Column('duration_ms', Float, nullable=False), Column('payload', Text, nullable=False),
    UniqueConstraint('owner', 'sha256', 'model_version'), Index('ix_owner_date_v1', 'owner', 'timestamp'))
experiments = Table('experiments_v1', metadata,
    Column('id', String(36), primary_key=True), Column('owner', String(128), nullable=False),
    Column('timestamp', String(40), nullable=False), Column('scan_id', String(36), nullable=False),
    Column('kind', String(30), nullable=False), Column('payload', Text, nullable=False),
    Index('ix_experiment_owner_date_v1', 'owner', 'timestamp'))


def validate_record(record: dict) -> None:
    try:
        UUID(record['scan_id'])
        if not re.fullmatch(r'[0-9a-f]{64}', record['sha256']):
            raise ValueError()
        if not re.fullmatch(r'[0-9a-f]{32}', record['md5']):
            raise ValueError()
        if type(record['size']) is not int or record['size'] <= 0:
            raise ValueError()
        if not math.isfinite(record['entropy']) or not 0 <= record['entropy'] <= 8:
            raise ValueError()
        if not isinstance(record['features'], dict) or not record['features'] or len(record['features']) > 100:
            raise ValueError()
        if any(not isinstance(k,str) or not isinstance(v,(int,float)) or not math.isfinite(v) or v < 0 for k,v in record['features'].items()):
            raise ValueError()
        if not isinstance(record['observations'],list) or len(record['observations']) > 100 or any(not isinstance(v,str) or len(v)>1000 for v in record['observations']):
            raise ValueError()
        if any(not isinstance(record[k],str) or len(record[k])>1000 for k in ('score_interpretation','follow_up')):
            raise ValueError()
        if record['verdict'] not in ('Malware', 'Legitimate') or record['risk'] not in ('High', 'Review', 'Low'):
            raise ValueError()
        if record['label'] != (0 if record['verdict'] == 'Malware' else 1):
            raise ValueError()
        if datetime.fromisoformat(record['timestamp']).utcoffset() != timedelta(0):
            raise ValueError()
        for key in ('confidence', 'malware_score'):
            if not math.isfinite(record[key]) or not 0 <= record[key] <= 1:
                raise ValueError()
        if not math.isfinite(record['duration_ms']) or record['duration_ms'] < 0:
            raise ValueError()
        if len(record['filename']) > 120 or len(record['model_version']) > 64 or record['format'] != 'PE':
            raise ValueError()
        if record['status'] != 'completed' or type(record['review']) is not bool:
            raise ValueError()
        if len(json.dumps(record, allow_nan=False)) > 100000:
            raise ValueError()
    except (KeyError, TypeError, ValueError, OverflowError, AttributeError):
        raise AnalysisError('Invalid scan record; nothing was stored.') from None


class Store:
    def __init__(self, url: str | None = None):
        if url is None:
            (ROOT / '.runtime').mkdir(exist_ok=True)
            url = 'sqlite:///' + (ROOT / '.runtime/scans.db').as_posix()
        if not url.startswith(('sqlite:///', 'postgresql+psycopg://')):
            raise AnalysisError('Use a SQLite or PostgreSQL psycopg database URL.')
        sqlite = url.startswith('sqlite')
        self.engine = create_engine(url, pool_pre_ping=True, pool_recycle=300,
                                   pool_size=4, max_overflow=4, pool_timeout=15,
                                   connect_args={'timeout': 15} if sqlite else {
                                       'connect_timeout': 10,
                                       'options': '-c statement_timeout=15000 -c lock_timeout=5000',
                                       'application_name': 'malguard'})
        if url.startswith('sqlite'):
            @event.listens_for(self.engine, 'connect')
            def configure(connection, _):
                connection.execute('PRAGMA journal_mode=WAL')
                connection.execute('PRAGMA busy_timeout=15000')
        # Serialize startup initialization across PostgreSQL workers/replicas.
        with self.engine.begin() as connection:
            if not sqlite: connection.execute(text('SELECT pg_advisory_xact_lock(1296516946)'))
            metadata.create_all(connection)
            versions = list(connection.execute(select(schema.c.version)).scalars())
            if not versions: connection.execute(schema.insert().values(version=1))
            elif versions != [1]:
                raise AnalysisError('Database schema is newer or incompatible. Use the matching application release; no records were changed.')

    def _where(self, owner: str, filters: dict | None = None):
        if not isinstance(owner, str) or not 16 <= len(owner) <= 128:
            raise AnalysisError('Invalid session scope.')
        clauses = [scans.c.owner == owner]
        for key, value in (filters or {}).items():
            if value in (None, '', 'All'):
                continue
            if key == 'start': clauses.append(scans.c.timestamp >= value)
            elif key == 'end': clauses.append(scans.c.timestamp < value)
            elif key == 'search': clauses.append(scans.c.filename.contains(value, autoescape=True) | scans.c.sha256.contains(value, autoescape=True))
            elif key in ('verdict', 'format', 'risk', 'model_version'): clauses.append(scans.c[key] == value)
            else: raise AnalysisError('Unsupported history filter.')
        return clauses

    def save(self, owner: str, record: dict) -> bool:
        self._where(owner)
        validate_record(record)
        row = {c: record[c] for c in ('scan_id','timestamp','sha256','filename','format','verdict','risk','model_version','duration_ms')}
        row.update(owner=owner, review=int(record['review']), payload=json.dumps(record, allow_nan=False))
        try:
            with self.engine.begin() as connection:
                connection.execute(scans.insert().values(**row))
            return True
        except IntegrityError:
            # Suppress only verified duplicate hash/model records; other constraints remain errors.
            with self.engine.connect() as connection:
                duplicate = connection.execute(select(scans.c.scan_id).where(scans.c.owner == owner, scans.c.sha256 == record['sha256'], scans.c.model_version == record['model_version'])).first()
            if duplicate: return False
            raise

    def records(self, owner: str, filters=None, limit=100, offset=0, ascending=False) -> list[dict]:
        if not 1 <= limit <= 1000 or not 0 <= offset <= 1000000:
            raise AnalysisError('History query exceeds its bounds.')
        order = scans.c.timestamp.asc() if ascending else scans.c.timestamp.desc()
        query = select(scans.c.payload).where(*self._where(owner, filters)).order_by(order, scans.c.scan_id).limit(limit).offset(offset)
        with self.engine.connect() as connection:
            result = []
            for row in connection.execute(query):
                try:
                    item = json.loads(row[0]); validate_record(item); result.append(item)
                except (ValueError, TypeError):
                    raise AnalysisError('Stored history contains an invalid record. Restore a backup or delete affected session records.') from None
            return result

    def by_hash(self, owner: str, digest: str, model_version: str) -> dict | None:
        rows = self.records(owner, {'search': digest, 'model_version': model_version}, limit=1)
        return rows[0] if rows else None

    def summary(self, owner: str, filters=None) -> dict:
        query = select(func.count().label('total'), func.count(func.distinct(scans.c.sha256)).label('unique_hashes'),
            func.sum(case((scans.c.verdict == 'Malware', 1), else_=0)).label('malware'),
            func.sum(scans.c.review).label('review'), func.avg(scans.c.duration_ms).label('average_ms')).where(*self._where(owner, filters))
        with self.engine.connect() as connection: values = dict(connection.execute(query).mappings().one())
        values = {k: (v or 0) for k,v in values.items()}
        values['legitimate'] = values['total'] - values['malware']
        values['malware_percent'] = 100*values['malware']/values['total'] if values['total'] else None
        return values

    def distribution(self, owner: str, dimension: str, filters=None) -> list[dict]:
        if dimension not in ('verdict', 'format', 'risk', 'model_version', 'day'):
            raise AnalysisError('Unknown distribution dimension.')
        key = func.substr(scans.c.timestamp, 1, 10) if dimension == 'day' else scans.c[dimension]
        query = select(key.label(dimension), scans.c.verdict, func.count().label('count')).where(*self._where(owner, filters)).group_by(key, scans.c.verdict).order_by(key)
        with self.engine.connect() as connection:
            return [dict(r) for r in connection.execute(query).mappings()]

    def delete(self, owner: str, scan_id: str | None = None) -> int:
        clauses = self._where(owner)
        if scan_id: clauses.append(scans.c.scan_id == scan_id)
        with self.engine.begin() as connection:
            exp = delete(experiments).where(experiments.c.owner == owner)
            if scan_id: exp = exp.where(experiments.c.scan_id == scan_id)
            connection.execute(exp)
            return connection.execute(delete(scans).where(*clauses)).rowcount

    def retain(self, days: int) -> int:
        if type(days) is not int or not 1 <= days <= 3650:
            raise AnalysisError('Retention must be 1–3650 days.')
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self.engine.begin() as connection:
            expired_scans = select(scans.c.scan_id).where(scans.c.timestamp < cutoff)
            connection.execute(delete(experiments).where(experiments.c.scan_id.in_(expired_scans)))
            connection.execute(delete(experiments).where(experiments.c.timestamp < cutoff))
            return connection.execute(delete(scans).where(scans.c.timestamp < cutoff)).rowcount

    def save_experiment(self, owner: str, scan_id: str, result: dict) -> None:
        from uuid import uuid4
        self._where(owner)
        if result.get('kind') not in ('feature_sensitivity', 'exposure'):
            raise AnalysisError('Unknown experiment type.')
        payload = json.dumps(result, allow_nan=False)
        if len(payload) > 1000000: raise AnalysisError('Experiment is too large.')
        with self.engine.begin() as connection:
            if scan_id and not connection.execute(select(scans.c.scan_id).where(scans.c.scan_id == scan_id, scans.c.owner == owner)).first():
                raise AnalysisError('The source scan is no longer available in your workspace. Scan the file again.')
            connection.execute(experiments.insert().values(id=str(uuid4()), owner=owner, scan_id=scan_id,
                timestamp=datetime.now(timezone.utc).isoformat(), kind=result['kind'], payload=payload))

    def experiments(self, owner: str) -> list[dict]:
        self._where(owner)
        with self.engine.connect() as connection:
            return [json.loads(r[0]) for r in connection.execute(select(experiments.c.payload).where(experiments.c.owner == owner).order_by(experiments.c.timestamp.desc()).limit(100))]

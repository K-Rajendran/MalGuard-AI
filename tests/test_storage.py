import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
from uuid import uuid4
import pytest
from malguard.core import AnalysisError
from malguard.reports import csv_report,json_report,summary
from malguard.storage import scans

OWNER = 'session-owner-test-0001'


def test_pipeline_history_analytics_export(store,record):
    assert store.save(OWNER,record)
    assert not store.save(OWNER,record)
    assert store.records('another-owner-0002') == []
    assert store.records(OWNER)[0] == record
    assert store.summary(OWNER)['total'] == 1
    assert store.summary(OWNER)['unique_hashes'] == 1
    assert store.summary(OWNER)['malware'] == (record['label']==0)
    assert sum(r['count'] for r in store.distribution(OWNER,'day')) == 1
    assert store.records(OWNER,{'search':"' OR 1=1 --"}) == []
    assert store.records(OWNER,{'search':'fixture'})
    assert record['sha256'] in json_report(record)
    assert record['sha256'] in csv_report([record])
    assert 'Uncalibrated' in summary(record)


def test_concurrent_duplicate_insertion(store,record):
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _:store.save(OWNER,record),range(8)))
    assert sum(results) == 1
    assert store.summary(OWNER)['total'] == 1


def test_retention_and_scoped_deletion(store,record):
    old = copy.deepcopy(record)
    old['timestamp'] = (datetime.now(timezone.utc)-timedelta(days=60)).isoformat()
    store.save(OWNER,old)
    other = copy.deepcopy(record); other['scan_id']=str(uuid4())
    store.save('other-session-owner',other)
    assert store.retain(30) == 1
    assert store.delete(OWNER) == 0
    assert store.summary('other-session-owner')['total'] == 1


def test_reject_corrupt_records(store,record):
    bad = dict(record,confidence=float('nan'))
    with pytest.raises(AnalysisError): store.save(OWNER,bad)
    store.save(OWNER,record)
    with store.engine.begin() as connection:
        connection.execute(scans.update().values(payload='broken'))
    with pytest.raises(AnalysisError): store.records(OWNER)


def test_experiments_separate(store,record):
    store.save(OWNER,record)
    store.save_experiment(OWNER,record['scan_id'],{'kind':'exposure','exposed':1})
    assert store.summary(OWNER)['total']==1
    assert len(store.experiments(OWNER))==1
    assert not store.experiments('other-session-owner')
    store.delete(OWNER,record['scan_id'])
    assert not store.experiments(OWNER)


def test_csv_formula_injection():
    assert "'=SUM" in csv_report([{'filename':'=SUM(A1)'}])


def test_experiment_cannot_reference_another_owner(store,record):
    store.save(OWNER,record)
    with pytest.raises(AnalysisError):
        store.save_experiment('another-owner-0002',record['scan_id'],{'kind':'exposure'})
    assert store.experiments('another-owner-0002')==[]


def test_incompatible_database_schema_is_rejected(store):
    from malguard.storage import schema, Store
    with store.engine.begin() as connection:
        connection.execute(schema.update().values(version=999))
    with pytest.raises(AnalysisError): Store(str(store.engine.url))


@pytest.mark.parametrize('field,value',[('size',-1),('entropy',9),('features',{}),('md5','bad'),('observations',[{}]),('scan_id','bad')])
def test_incomplete_or_invalid_metadata_rejected(store,record,field,value):
    record[field]=value
    with pytest.raises(AnalysisError): store.save(OWNER,record)


def test_retention_removes_recent_experiments_linked_to_expired_scan(store,record):
    record['timestamp']=(datetime.now(timezone.utc)-timedelta(days=60)).isoformat()
    store.save(OWNER,record)
    store.save_experiment(OWNER,record['scan_id'],{'kind':'exposure','exposed':1})
    store.retain(30)
    assert store.experiments(OWNER)==[]


def test_all_filters_pagination_and_kpis(store,record):
    for index in range(3):
        item=copy.deepcopy(record)
        item.update(scan_id=str(uuid4()),sha256=f'{index:064x}',timestamp=f'2026-01-0{index+1}T12:00:00+00:00',
                    duration_ms=100*(index+1),model_version='v2' if index==2 else 'v1')
        if index==1:
            item.update(label=1,verdict='Legitimate',risk='Low',review=False,malware_score=.1,confidence=.9)
        else:
            item.update(label=0,verdict='Malware',risk='High',review=True,malware_score=.7,confidence=.7)
        store.save(OWNER,item)
    values=store.summary(OWNER)
    assert values['total']==3 and values['malware']==2 and values['legitimate']==1 and values['review']==2
    assert values['average_ms']==200 and values['malware_percent']==pytest.approx(200/3)
    for filters,count in [({'verdict':'Malware'},2),({'risk':'Low'},1),({'format':'PE'},3),({'model_version':'v2'},1),
                          ({'start':'2026-01-02','end':'2026-01-03'},1),({'verdict':'Legitimate','risk':'High'},0)]:
        assert store.summary(OWNER,filters)['total']==count
        assert len(store.records(OWNER,filters))==count
    pages=[store.records(OWNER,limit=1,offset=i,ascending=True)[0] for i in range(3)]
    assert len({r['scan_id'] for r in pages})==3
    assert [r['timestamp'] for r in pages]==sorted(r['timestamp'] for r in pages)
    for dimension in ('day','format','risk','model_version'):
        assert sum(r['count'] for r in store.distribution(OWNER,dimension))==3

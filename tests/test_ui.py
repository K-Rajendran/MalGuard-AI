"""Real Streamlit reruns with isolated storage and non-executing file analysis."""
import pytest
from streamlit.testing.v1 import AppTest
from malguard.ui import PAGES
from malguard.core import ROOT


@pytest.fixture
def app(tmp_path,monkeypatch):
    monkeypatch.setenv('MALGUARD_DATABASE_URL','sqlite:///'+(tmp_path/'ui.db').as_posix())
    result=AppTest.from_file(ROOT/'streamlit_app.py',default_timeout=30).run()
    assert not result.exception
    return result


@pytest.mark.parametrize('page',PAGES)
def test_pages_render(app,page):
    app.sidebar.radio[0].set_value(page).run()
    assert not app.exception
    assert not app.error
    assert app.title


def test_navigation_action(app):
    app.button[0].click().run()
    assert app.sidebar.radio[0].value=='Malware Scanner'
    assert not app.exception


def test_production_configuration_failure_blocks_all_workflows(monkeypatch):
    monkeypatch.setenv('MALGUARD_MODE','production')
    monkeypatch.delenv('MALGUARD_DATABASE_URL',raising=False)
    result=AppTest.from_file(ROOT/'streamlit_app.py',default_timeout=30).run()
    assert not result.exception
    assert result.error and 'PostgreSQL' in result.error[0].value
    assert not result.sidebar.radio


def test_animations_can_be_disabled_without_losing_navigation(app):
    next(c for c in app.checkbox if c.label=='Show animations').uncheck().run()
    app.sidebar.radio[0].set_value('File Security').run()
    assert not app.exception and not app.error
    assert app.title[0].value=='File Security'
    assert app.session_state['show_animations'] is False


def test_real_scan_dashboard_history_resilience_exposure(app,record):
    from malguard.ui import database
    import os
    store=database(os.environ['MALGUARD_DATABASE_URL'])
    owner=app.session_state['owner']
    store.save(owner,record)
    app.session_state['active_scan']=record
    app.sidebar.radio[0].set_value('Threat Intelligence').run()
    assert not app.error and not app.exception
    assert app.metric[0].value=='1'
    app.sidebar.radio[0].set_value('Scan History & Reports').run()
    assert not app.error and not app.exception
    assert len(app.dataframe)>0
    app.sidebar.radio[0].set_value('Resilience Lab').run()
    next(b for b in app.button if b.label=='Run sensitivity analysis').click().run()
    assert not app.error and not app.exception
    assert app.session_state['resilience_result']['count']==24
    app.sidebar.radio[0].set_value('Exposure Simulator').run()
    next(c for c in app.checkbox if c.label=='Use the clearly labeled example environment').check().run()
    next(b for b in app.button if b.label=='Simulate exposure').click().run()
    assert not app.error and not app.exception
    assert app.session_state['exposure_result']['exposed']==2
    assert store.summary(owner)['total']==1


def test_corrupt_history_retains_deletion_controls(app,record):
    from malguard.ui import database
    from malguard.storage import scans
    import os
    store=database(os.environ['MALGUARD_DATABASE_URL'])
    owner=app.session_state['owner']
    store.save(owner,record)
    with store.engine.begin() as connection:
        connection.execute(scans.update().values(payload='corrupt'))
    app.sidebar.radio[0].set_value('Scan History & Reports').run()
    assert not app.exception
    assert app.error
    next(c for c in app.checkbox if c.label=='Confirm deletion of all records in this workspace').check().run()
    next(b for b in app.button if b.label=='Delete workspace history').click().run()
    assert store.summary(owner)['total']==0
    assert not app.exception

import time
import pytest
from malguard.core import AnalysisError
from malguard.settings import load_settings, authenticated_owner

AUTH = {'redirect_uri':'https://example.test/oauth2callback','cookie_secret':'s'*40,
        'client_id':'test','client_secret':'test','server_metadata_url':'https://id.example.test/.well-known/openid-configuration'}
PRODUCTION = {'MALGUARD_MODE':'production','MALGUARD_DATABASE_URL':'postgresql+psycopg://user:password@db.example.test/malguard?sslmode=verify-full','auth':AUTH}

def test_local_and_secret_settings():
    assert not load_settings({},{}).production
    result=load_settings(PRODUCTION,{})
    assert result.production and result.database_url.startswith('postgresql')
    assert load_settings({'MALGUARD_RETENTION_DAYS':15},{'MALGUARD_RETENTION_DAYS':'7'}).retention_days==7

@pytest.mark.parametrize('url',[None,'sqlite:///history.db','sqlite:///:memory:',
    'postgresql+psycopg://u:p@db/test','postgresql+psycopg://u:p@db/test?sslmode=disable'])
def test_production_never_falls_back_to_local_or_unverified_tls(url):
    with pytest.raises(AnalysisError): load_settings(dict(PRODUCTION,MALGUARD_DATABASE_URL=url),{})

@pytest.mark.parametrize('auth',[{},dict(AUTH,cookie_secret='short'),dict(AUTH,redirect_uri='http://example.test/oauth2callback')])
def test_production_requires_secure_signin(auth):
    with pytest.raises(AnalysisError): load_settings(dict(PRODUCTION,auth=auth),{})

def test_owner_stable_private_and_access_controlled():
    claims={'iss':'https://issuer.example','sub':'user-123','exp':time.time()+600}
    owner=authenticated_owner(claims)
    assert owner==authenticated_owner(dict(claims,email='changed@example.test'))
    assert owner!=authenticated_owner(dict(claims,iss='https://another.example'))
    assert 'user-123' not in owner
    assert authenticated_owner(claims,('user-123',))==owner
    for invalid in [dict(claims,exp=0),dict(claims,exp=float('nan')),dict(claims,sub=None),dict(claims,iss=None)]:
        with pytest.raises(AnalysisError): authenticated_owner(invalid)
    with pytest.raises(AnalysisError): authenticated_owner(claims,('another-user',))

def test_bad_configuration_is_actionable():
    for env in [{'MALGUARD_MODE':'prod'},{'MALGUARD_RETENTION_DAYS':'oops'},{'MALGUARD_RETENTION_DAYS':'0'}]:
        with pytest.raises(AnalysisError): load_settings({},env)


@pytest.mark.parametrize('error_id',['failed-parsing-secrets-file','invalid-secrets-path','no-secrets-found'])
def test_malformed_secrets_never_silently_enable_local_mode(monkeypatch,error_id):
    from streamlit.errors import StreamlitSecretNotFoundError
    from malguard.ui import read_secrets,st
    def fail(): raise StreamlitSecretNotFoundError('Private details must not leak',error_id=error_id)
    monkeypatch.setattr(type(st.secrets),'to_dict',lambda self:fail())
    if error_id=='no-secrets-found': assert read_secrets()=={}
    else:
        with pytest.raises(AnalysisError,match='access is blocked'): read_secrets()

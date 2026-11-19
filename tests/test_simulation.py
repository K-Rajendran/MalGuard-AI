import copy
import io
import json
import pytest
from ruamel.yaml import YAML
from malguard.simulation import EXAMPLE,parse_profile,graph,simulate,graph_html
from malguard.core import AnalysisError


def test_json_yaml_graph_exposure_remediation(record):
    data=json.dumps(EXAMPLE).encode()
    assert parse_profile(data,'json')==EXAMPLE
    output=io.StringIO(); YAML().dump(EXAMPLE,output)
    assert parse_profile(output.getvalue().encode(),'yaml')==EXAMPLE
    assert len(graph(EXAMPLE))==3
    result=simulate(EXAMPLE,'workstation',scan=record)
    assert result['exposed']==2 and result['direct']==1
    assert result['assets'][1]['path']==['workstation','files']
    assert result['file_evidence']['sha256']==record['sha256']
    assert simulate(EXAMPLE,'workstation',isolate=['files'])['exposed']==1
    assert simulate(EXAMPLE,'workstation',isolate=['workstation'])['exposed']==0
    assert result['assets'][1]['mitigations']


@pytest.mark.parametrize('data,fmt',[(b'!!python/object/apply:os.system [calc]','yaml'),(b'a: &x [*x]','yaml'),(b'{"hosts":[],"hosts":[]}','json'),(b'hosts: broken','yaml'),(b'{','json')])
def test_unsafe_profiles(data,fmt):
    with pytest.raises(AnalysisError): parse_profile(data,fmt)


@pytest.mark.parametrize('mutation',['port','duplicate','edge','size','field'])
def test_schema_limits(mutation):
    data=copy.deepcopy(EXAMPLE)
    if mutation=='port': data['hosts'][1]['services'][0]['port']=70000
    if mutation=='duplicate': data['hosts'][1]['id']='workstation'
    if mutation=='edge': data['connections'][0]['target']='unknown'
    if mutation=='size': data['hosts']*=40
    if mutation=='field': data['hosts'][0]['secret']='unexpected'
    with pytest.raises(AnalysisError): parse_profile(json.dumps(data).encode(),'json')


def test_graph_html_escapes_untrusted_labels():
    profile=copy.deepcopy(EXAMPLE)
    profile['hosts'][0]['hostname']='</script><img src=x onerror=alert(1)>'
    result=simulate(profile,'workstation')
    document=graph_html(profile,result)
    assert '<img src=x' not in document
    assert '<script src=' not in document
    assert 'vis.Network' in document

"""Non-executing infrastructure exposure hypotheses, never a network scanner."""
import html
import json
import re
import networkx as nx
from jsonschema import Draft202012Validator
from ruamel.yaml import YAML
from ruamel.yaml.events import AliasEvent, MappingStartEvent, MappingEndEvent, SequenceStartEvent, SequenceEndEvent
from .core import AnalysisError, validate_bytes

TEXT = {'type': 'string', 'maxLength': 120}
IDENTIFIER = {'type': 'string', 'pattern': '^[a-zA-Z0-9_-]{1,40}$'}
APPLICATION = {'type': 'object', 'additionalProperties': False, 'required': ['name','version'], 'properties': {'name': TEXT, 'version': TEXT}}
SERVICE = {'type': 'object', 'additionalProperties': False, 'required': ['name','port'], 'properties': {'name': TEXT, 'port': {'type':'integer','minimum':1,'maximum':65535}}}
SCHEMA = {'type':'object', 'additionalProperties':False, 'required':['hosts','connections'], 'properties': {
    'hosts': {'type':'array','minItems':1,'maxItems':100,'items': {
        'type':'object','additionalProperties':False,'required':['id','hostname','os','zone','criticality'], 'properties': {
            'id': IDENTIFIER, 'hostname':TEXT, 'os':TEXT, 'os_version':TEXT, 'zone':TEXT,
            'criticality':{'type':'integer','minimum':1,'maximum':5},
            'applications':{'type':'array','maxItems':30,'items':APPLICATION},
            'services':{'type':'array','maxItems':30,'items':SERVICE},
            'controls':{'type':'array','maxItems':3,'uniqueItems':True,'items':{'enum':['isolated','endpoint_protection','least_privilege']}}}}},
    'connections': {'type':'array','maxItems':500,'items':{'type':'object','additionalProperties':False,
        'required':['source','target'], 'properties':{'source':IDENTIFIER,'target':IDENTIFIER}}}}}

EXAMPLE = {'hosts':[
    {'id':'workstation','hostname':'analyst-pc','os':'Windows','os_version':'11','zone':'office','criticality':2,
     'applications':[{'name':'Browser','version':'user-supplied'}], 'services':[], 'controls':['endpoint_protection']},
    {'id':'files','hostname':'file-server','os':'Windows','os_version':'Server 2022','zone':'servers','criticality':5,
     'applications':[], 'services':[{'name':'SMB','port':445}], 'controls':['least_privilege']},
    {'id':'backup','hostname':'backup','os':'Linux','os_version':'user-supplied','zone':'backup','criticality':5,
     'applications':[], 'services':[], 'controls':['isolated']}],
    'connections':[{'source':'workstation','target':'files'},{'source':'files','target':'backup'}]}


def validate_profile(profile: dict) -> dict:
    try:
        error = next(Draft202012Validator(SCHEMA).iter_errors(profile), None)
    except (RecursionError, TypeError):
        raise AnalysisError('Invalid infrastructure profile.') from None
    if error:
        location = '.'.join(map(str,error.absolute_path)) or 'root'
        raise AnalysisError(f'Profile validation failed at {location}: check required fields, types and limits in README.')
    ids = [host['id'] for host in profile['hosts']]
    if len(set(ids)) != len(ids): raise AnalysisError('Host identifiers must be unique.')
    edges = [(c['source'], c['target']) for c in profile['connections']]
    if len(set(edges)) != len(edges): raise AnalysisError('Duplicate connections are not allowed.')
    if any(a not in ids or b not in ids or a == b for a,b in edges):
        raise AnalysisError('Connections must reference distinct existing hosts.')
    return profile


def parse_profile(data: bytes, format: str) -> dict:
    validate_bytes(data, 256*1024)
    try:
        text = data.decode('utf-8')
        if format.lower() == 'json':
            def pairs(values):
                result = {}
                for key,value in values:
                    if key in result: raise ValueError('Duplicate key')
                    result[key] = value
                return result
            profile = json.loads(text, object_pairs_hook=pairs)
        elif format.lower() in ('yaml','yml'):
            parser = YAML(typ='safe', pure=True)
            depth = count = 0
            for event in parser.parse(text):
                count += 1
                if isinstance(event, AliasEvent): raise ValueError('YAML aliases are disabled')
                if isinstance(event, (MappingStartEvent, SequenceStartEvent)): depth += 1
                if isinstance(event, (MappingEndEvent, SequenceEndEvent)): depth -= 1
                if depth > 12 or count > 30000: raise ValueError('YAML complexity limit')
            profile = YAML(typ='safe', pure=True).load(text)
        else:
            raise ValueError('Unsupported profile format')
        return validate_profile(profile)
    except AnalysisError:
        raise
    except Exception:
        raise AnalysisError('Invalid JSON/YAML. Use UTF-8, unique keys, no aliases or object tags, and the documented schema.') from None


def graph(profile: dict) -> nx.DiGraph:
    validate_profile(profile)
    result = nx.DiGraph()
    result.add_nodes_from((h['id'], h) for h in profile['hosts'])
    result.add_edges_from((c['source'],c['target']) for c in profile['connections'])
    return result


def simulate(profile: dict, initial: str, windows_only: bool = True, isolate: list[str] | None = None, scan: dict | None = None) -> dict:
    network = graph(profile)
    if initial not in network: raise AnalysisError('Choose an initial host in the profile.')
    isolate = isolate or []
    if any(node not in network for node in isolate): raise AnalysisError('Unknown isolated host.')
    allowed = [n for n,h in network.nodes(data=True) if 'isolated' not in h.get('controls',[]) and n not in isolate
               and (not windows_only or h['os'].lower().startswith('windows'))]
    reachable_graph = network.subgraph(allowed)
    paths = nx.single_source_shortest_path(reachable_graph, initial) if initial in reachable_graph else {}
    assets = []
    for node, host in network.nodes(data=True):
        path = paths.get(node, [])
        services = host.get('services',[])
        controls = host.get('controls',[])
        score = max(0, min(100, 20+12*host['criticality']+min(20,5*len(services))
                         -15*('endpoint_protection' in controls)-10*('least_privilege' in controls))) if path else 0
        reasons = []
        if path:
            reasons.append('Initial exposure assumption' if node == initial else 'Reachable through supplied directed connections')
            reasons.append(f"Criticality {host['criticality']}/5 and {len(services)} supplied services")
        else: reasons.append('Unreachable, isolated, or excluded by OS assumption')
        mitigations = []
        if path and services: mitigations.append('Restrict unnecessary listed services: '+', '.join(str(s['port']) for s in services))
        if path and node != initial: mitigations.append('Review or remove incoming permitted communication paths; test segmentation.')
        if path and 'endpoint_protection' not in controls: mitigations.append('Evaluate endpoint protection on this asset.')
        if path and 'least_privilege' not in controls: mitigations.append('Review least-privilege access for this asset.')
        if host.get('applications') and path: mitigations.append('Verify patch status of listed application versions; no vulnerability lookup was performed.')
        assets.append({'id':node,'hostname':host['hostname'],'score':score,'path':path,'distance':len(path)-1 if path else None,
                       'priority':'High' if score >= 70 else ('Moderate' if path else 'Unreachable/protected'),
                       'reasons':reasons,'mitigations':mitigations})
    return {'kind':'exposure','initial':initial,'total':len(network),'exposed':len(paths),
            'direct':sum(len(p)==2 for p in paths.values()), 'secondary':sum(len(p)>2 for p in paths.values()),
            'assets':assets,'assumptions':{'windows_only':windows_only,'isolated_hosts':isolate,
                'scenario':'Generic reachability; supplied controls are assumed effective. No capabilities inferred from ML score.'},
            'file_evidence':{k:scan[k] for k in ('sha256','format','verdict','model_version')} if scan else None,
            'kill_chain': [{'stage':'Initial exposure','basis':'User-selected host; hypothetical'},
                           {'stage':'Potential execution opportunity','basis':'OS compatibility assumption only; no execution observed'},
                           {'stage':'Possible lateral exposure','basis':'Supplied directed paths; no exploitation inferred'},
                           {'stage':'Potential impact','basis':'User-supplied asset criticality; no damage observed'}],
            'limitations':'Scores rank scenario priorities, not compromise probabilities. Connectivity and controls are unverified user inputs.'}


def graph_html(profile: dict, result: dict) -> str:
    from pyvis.network import Network
    network = graph(profile)
    vis = Network(height='520px', width='100%', directed=True, bgcolor='#FFFFFF', font_color='#132547', cdn_resources='in_line')
    indexed = {a['id']:a for a in result['assets']}
    for node, host in network.nodes(data=True):
        asset = indexed[node]
        color = '#09318D' if node == result['initial'] else ('#AD397E' if asset['score'] >= 70 else ('#FD91CC' if asset['path'] else '#CBD2E1'))
        vis.add_node(node, label=html.escape(host['hostname']), color=color,
                     title=html.escape(f"{host['hostname']} | {host['zone']} | Priority score {asset['score']} | " + '; '.join(asset['reasons'])))
    for source,target in network.edges: vis.add_edge(source,target,color='#597CC8')
    vis.set_options('{"physics":{"enabled":false},"interaction":{"hover":true,"navigationButtons":true}}')
    output = vis.generate_html(notebook=False)
    # PyVis includes optional external Bootstrap assets despite inline vis resources.
    output = re.sub(r'<script\b[^>]*\bsrc=[^>]*>\s*</script>', '', output, flags=re.I)
    output = re.sub(r'<link\b[^>]*>', '', output, flags=re.I)
    return output

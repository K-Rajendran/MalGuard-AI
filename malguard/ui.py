"""Native Streamlit investigation console with explicit action boundaries."""
from datetime import datetime, timedelta, timezone
import copy
import logging
import secrets
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
from . import crypto, resilience, simulation
from .core import AnalysisError, LOGGER, MAX_UPLOAD, safe_name, sha256
from .ml import load_model
from .reports import csv_report, json_report, summary
from .scanner import scan
from .storage import Store
from .intelligence import trend_counts
from .presentation import apply_theme, page_header, explain, animation_html, BLUE, PINK
from .settings import load_settings, authenticated_owner


def read_secrets():
    from streamlit.errors import StreamlitSecretNotFoundError
    try:
        return st.secrets.to_dict()
    except StreamlitSecretNotFoundError as exc:
        if exc.error_id == 'no-secrets-found': return {}
        raise AnalysisError('The secrets configuration cannot be read. Fix it before starting; access is blocked.') from None

PAGES = ['Overview','Malware Scanner','Threat Intelligence','File Security','Resilience Lab',
         'Exposure Simulator','Scan History & Reports','Model Insights']


@st.cache_resource
def database(url):
    return Store(url or None)


def _result(record):
    st.subheader(record['filename'])
    a,b,c = st.columns(3)
    a.metric('Model prediction', record['verdict'])
    b.metric('Malware score', f"{record['malware_score']:.1%}")
    c.metric('Analyst review', 'Required' if record['review'] else 'Standard')
    st.caption(record['score_interpretation'])
    st.write('**What this means:** '+('The model found patterns associated with malware. Keep this file closed and ask a security professional to review it.' if record['label']==0 else 'The model found patterns associated with legitimate software. Check the source before opening it; this is not a safety certificate.'))
    explain('How to read this result',
            '**Malware score** describes how strongly the model favors the malware class; 80% is not an 80% real-world chance of infection. '
            '**Analyst review: Required** means neither class received a score of at least 80%, so the answer needs extra checking. '
            '**SHA-256** below is a file fingerprint: identical bytes produce the same value. '
            '**Entropy** measures how varied the file’s bytes are, from 0 to 8; compressed or encrypted legitimate files can also score highly.')
    if record['label']==0 and st.session_state.get('show_animations',True):
        with st.expander('Detection illustration'):
            components.html(animation_html('malwaredetected.json'),height=170)
    (st.warning if record['label'] == 0 or record['review'] else st.info)(record['follow_up'])
    st.code(record['sha256'], language=None)
    with st.expander('Observed file metadata and technical evidence'):
        st.json({k:v for k,v in record.items() if k != 'features'})
        st.dataframe(pd.DataFrame(record['features'].items(), columns=['Feature','Observed value']), hide_index=True)
    a,b = st.columns(2)
    a.download_button('Download scan JSON', json_report(record), 'malguard-scan.json','application/json', key='json'+record['scan_id'])
    b.download_button('Download readable summary', summary(record), 'malguard-scan.txt','text/plain', key='text'+record['scan_id'])


def overview(store, owner):
    page_header('Security workspace')
    st.write('Inspect a Windows executable. Review the evidence. Test the assumptions.')
    values = store.summary(owner)
    a,b,c,d = st.columns(4)
    for column,label,key in zip((a,b,c,d),('Scans in this workspace','Malware predictions','Review required','Unique file hashes'),('total','malware','review','unique_hashes')):
        column.metric(label,values[key])
    st.divider()
    a,b = st.columns([3,2])
    with a:
        st.subheader('From file to investigation')
        st.write('**Observe** — SHA-256 fingerprints, executable metadata and static features.')
        st.write('**Assess** — trained malware classification, score limits and scan history.')
        st.write('**Explore** — bounded model sensitivity and hypothetical environment exposure.')
        st.button('Open malware scanner', type='primary', on_click=lambda: st.session_state.update(nav='Malware Scanner'))
    with b:
        with st.container(border=True):
            st.subheader('Workspace boundaries')
            st.write('Files are parsed as data and never executed. Original file bytes are not written to scan history.')
            st.caption('Local threat intelligence reflects your scan records. No global reputation feed or external file upload is enabled.')
    recent = store.records(owner,limit=5)
    if recent:
        st.subheader('Recent investigations')
        st.dataframe(pd.DataFrame(recent)[['timestamp','filename','verdict','risk']], hide_index=True)
    else:
        st.info('No scans yet. Open Malware Scanner to begin; statistics will appear after successful analysis.')


def scanner_page(store, owner):
    page_header('Malware Scanner')
    st.write('Static analysis for Windows PE executables and DLLs. Other formats receive no malware verdict.')
    keep = st.checkbox('Include filename in scan history', value=True)
    files = st.file_uploader('Choose files to analyze', accept_multiple_files=True, key='scan_upload', max_upload_size=MAX_UPLOAD // 1048576)
    st.caption(f'Up to 10 files per action, {MAX_UPLOAD // 1048576} MiB per file. Duplicate hashes for the same model are counted once per workspace.')
    if st.button('Analyze files', type='primary', disabled=not files):
        if len(files) > 10: raise AnalysisError('Select at most 10 files per action.')
        results = []
        for uploaded in files:
            with st.spinner('Extracting static features and evaluating the model…'):
                try:
                    record = scan(uploaded.getvalue(), uploaded.name, keep)
                    added = store.save(owner, record)
                    if not added:
                        st.info('This hash and model already exist in this workspace; displaying the stored analysis. History totals are unchanged.')
                        record = store.by_hash(owner,record['sha256'],record['model_version']) or record
                    results.append(record)
                except AnalysisError as exc:
                    st.error(str(exc))
        st.session_state['scan_results'] = results
        if results: st.session_state['active_scan'] = results[-1]
    for result in st.session_state.get('scan_results',[]):
        _result(result)


def filters(store, owner):
    a,b = st.columns(2)
    today = datetime.now(timezone.utc).date()
    start = a.date_input('From (UTC)', today-timedelta(days=30), key='filter_start')
    end = b.date_input('Through (UTC)', today, key='filter_end')
    if start > end: raise AnalysisError('Start date must be on or before end date.')
    a,b,c,d = st.columns(4)
    verdict = a.selectbox('Prediction',['All','Malware','Legitimate'])
    risk = b.selectbox('Risk category',['All','High','Review','Low'])
    fmt = c.selectbox('File format',['All','PE'])
    versions = sorted({r['model_version'] for r in store.distribution(owner,'model_version')})
    version = d.selectbox('Model version',['All']+versions)
    return {'start':start.isoformat(), 'end':(end+timedelta(days=1)).isoformat(),
            'verdict':verdict,'risk':risk,'format':fmt,'model_version':version}


def intelligence(store, owner):
    page_header('Threat Intelligence')
    explain('What do these numbers tell me?',
            '**Total scans** counts saved file checks; checking the same file again with the same model does not add another record. '
            '**Malware predictions** are model warnings, not confirmed infections. **Legitimate predictions** are not guarantees of safety. '
            '**Review required** overlaps those two categories and flags uncertain answers. '
            '**Detection percentage** is the share of your checks flagged as malware, not model accuracy. '
            '**Mean scan time** is the average processing time. Trends help you find busy periods; they do not measure attacks across the internet.')
    st.caption('Local scan analytics • UTC • Observed records only')
    selected = filters(store,owner)
    values = store.summary(owner,selected)
    a,b,c,d = st.columns(4)
    a.metric('Total scans',values['total']); b.metric('Malware predictions',values['malware'])
    c.metric('Legitimate predictions',values['legitimate']); d.metric('Review required',values['review'])
    a,b,c = st.columns(3)
    a.metric('Malware detection percentage','—' if values['malware_percent'] is None else f"{values['malware_percent']:.1f}%")
    b.metric('Unique hashes',values['unique_hashes']); c.metric('Mean scan time',f"{values['average_ms']:.0f} ms")
    st.caption('Review is an uncertainty flag (winning-class score < 0.80), not a third trained class; it overlaps the two predictions.')
    if not values['total']: st.info('No scans match these filters. Analyze a PE file or widen the date range.'); return
    a,b = st.columns(2)
    for col,dimension in ((a,'risk'),(b,'format')):
        rows = pd.DataFrame(store.distribution(owner,dimension,selected))
        col.plotly_chart(px.bar(rows,x=dimension,y='count',color='verdict',title=f'Detection by {dimension}', color_discrete_map={'Malware':PINK,'Legitimate':BLUE}),width='stretch')
    period = st.selectbox('Trend interval',['Daily','Weekly','Monthly'])
    grouped = trend_counts(store.distribution(owner,'day',selected),period)
    st.plotly_chart(px.line(grouped,x='day',y='count',color='verdict',markers=True,title='Scan volume and malware predictions'),width='stretch')
    st.caption('UTC calendar intervals: weekly points end on Sunday; monthly points start on the first day.')
    recent = store.records(owner,selected,limit=1000)
    df = pd.DataFrame(recent)
    st.caption('The following indicator distributions use up to the latest 1,000 matching records. KPIs and time trends above include all matching records.')
    a,b = st.columns(2)
    a.plotly_chart(px.histogram(df,x='entropy',color='verdict',title='Observed file entropy'),width='stretch')
    b.plotly_chart(px.histogram(df,x='malware_score',color='verdict',title='Uncalibrated malware scores'),width='stretch')
    repeated = df.groupby('sha256').agg(records=('scan_id','count'),models=('model_version','nunique')).reset_index()
    st.subheader('Hash correlation across models')
    st.dataframe(repeated[repeated.records>1],hide_index=True)


def file_security():
    page_header('File Security')
    st.info('For a new file, choose Encrypt and AES-GCM, enter a strong password, then download the result. Keep the password separately: forgotten passwords cannot be recovered. To reopen the file, choose Decrypt and Auto AES.')
    st.write('Protect a file with authenticated AES encryption, or open a supported legacy encrypted file.')
    action = st.radio('Operation',['Encrypt','Decrypt'],horizontal=True)
    algorithm = st.selectbox('Algorithm',['AES-GCM','AES Crypt (legacy)','DES (legacy)'] if action == 'Encrypt' else ['Auto AES','DES (legacy)'])
    permitted = True
    if algorithm == 'DES (legacy)':
        st.warning('DES-ECB is insecure and unauthenticated. Wrong keys or tampering can occasionally produce plausible output. Use it only for legacy compatibility.')
        permitted = st.checkbox('I understand the legacy DES limitations')
    elif algorithm == 'AES Crypt (legacy)':
        st.info('AES Crypt v2 compatibility matches the original pyAesCrypt workflow. AES-GCM is the recommended new format.')
    # Ciphertext adds headers/tags, so a maximum-size plaintext must remain uploadable for decryption.
    uploaded = st.file_uploader('Select a file',key='crypto_upload',max_upload_size=MAX_UPLOAD // 1048576 + (1 if action == 'Decrypt' else 0))
    with st.form('crypto_form',clear_on_submit=True):
        password = st.text_input('Password / legacy DES key',type='password')
        submitted = st.form_submit_button(action+' file',disabled=not uploaded or not permitted)
    signature = (action,algorithm,sha256(uploaded.getvalue()) if uploaded else None)
    if st.session_state.get('crypto_signature') != signature: st.session_state.pop('crypto_output',None)
    if submitted:
        st.session_state.pop('crypto_output',None)
        with st.spinner('Processing file protection…'):
            data = uploaded.getvalue()
            output = crypto.encrypt(data,password,algorithm) if action == 'Encrypt' else crypto.decrypt(data,password,algorithm)
            suffix = ('.des' if algorithm == 'DES (legacy)' else '.aes') if action == 'Encrypt' else '.decrypted'
            st.session_state['crypto_output'] = (output,safe_name(uploaded.name)+suffix)
            st.session_state['crypto_signature'] = signature
            st.success('File processed. Download the result below.')
    if 'crypto_output' in st.session_state:
        data,name = st.session_state['crypto_output']
        st.download_button('Download processed file',data,name,'application/octet-stream')
        if st.button('Clear processed file from session'):
            st.session_state.pop('crypto_output',None); st.rerun()
    st.caption('Passwords are not persisted or logged. Uploads and results stay in session memory; source files are never deleted or overwritten.')


def select_scan(store,owner):
    options = store.records(owner,limit=100)
    active = st.session_state.get('active_scan')
    if active and all(r['scan_id'] != active['scan_id'] for r in options): options.insert(0,active)
    if not options:
        st.info('Analyze a PE file in Malware Scanner first, then return here.'); return None
    selected = st.selectbox('Source analysis',range(len(options)),format_func=lambda i: f"{options[i]['filename']} · {options[i]['sha256'][:12]} · {options[i]['model_version']}")
    record = options[selected]
    if record['model_version'] != load_model()[1]['artifact_sha256'][:12]:
        st.warning('This scan uses a different model. Rescan before running feature sensitivity.'); return None
    return record


def resilience_page(store,owner):
    page_header('Resilience Lab')
    explain('How to run and interpret an experiment',
            'First scan a file, then select it here. **Dimensions** are file-information fields to vary; the technical names match the model. '
            '**Strength** controls the size of each numerical change. **Scenarios** is the number of model checks. '
            '**Seed** lets you repeat the same experiment. A **flip** means the model changed its verdict. '
            '**100% stability** means no verdict changed in these checks; it does not prove the file is safe or the model cannot be fooled. '
            '**Score deviation** is the change from the original malware score: 0.10 means 10 percentage points.')
    st.write('Measure model stability under bounded metadata-feature variations. No file is mutated or executed.')
    record = select_scan(store,owner)
    if record is None: return
    names = {'MajorLinkerVersion':'Build-tool version: major','MinorLinkerVersion':'Build-tool version: minor',
             'MajorImageVersion':'Program version: major','MinorImageVersion':'Program version: minor',
             'MajorOperatingSystemVersion':'Required OS version: major','MinorOperatingSystemVersion':'Required OS version: minor',
             'CheckSum':'File checksum field (internal numeric value)'}
    dimensions = st.multiselect('Scenario dimensions',resilience.DIMENSIONS,default=list(resilience.DIMENSIONS[:3]),format_func=lambda key:names[key])
    a,b,c = st.columns(3)
    strength = a.slider('Perturbation strength',.01,.5,.1,.01)
    count = b.number_input('Scenarios',1,128,24)
    seed = c.number_input('Reproducibility seed',0,4294967295,42)
    signature = (record['sha256'],record['model_version'],tuple(dimensions),strength,count,seed)
    if st.session_state.get('resilience_signature') != signature: st.session_state.pop('resilience_result',None)
    a,b = st.columns(2)
    if a.button('Run sensitivity analysis',type='primary'):
        with st.spinner('Evaluating bounded scenarios…'):
            result = resilience.evaluate(record['features'],dimensions,strength,int(count),int(seed))
            result['source_sha256'] = record['sha256']
            store.save_experiment(owner,record['scan_id'],result)
            st.session_state['resilience_result'] = result
            st.session_state['resilience_signature'] = signature
    if b.button('Reset results'): st.session_state.pop('resilience_result',None)
    result = st.session_state.get('resilience_result')
    if not result: return
    a,b = st.columns([1,2])
    a.plotly_chart(go.Figure(go.Indicator(mode='gauge+number',value=result['stability_percent'],title={'text':'Scenario stability (%)'},gauge={'axis':{'range':[0,100]},'bar':{'color':BLUE}})),width='stretch')
    df = pd.DataFrame(result['scenarios'])
    fig = px.scatter(df,x='scenario',y='malware_score',color='dimension',title='Baseline versus scenario score')
    fig.add_hline(y=result['baseline']['malware_score'],line_dash='dash',annotation_text='Baseline')
    b.plotly_chart(fig,width='stretch')
    st.write(f"**{result['interpretation']}** — {result['stable']} stable predictions; {result['flips']} flips in {result['count']} scenarios.")
    st.caption('Stability = 100 × unchanged predictions / valid scenarios. '+result['limitation'])
    st.write(f"Maximum score deviation: {result['max_score_deviation']:.4f}; mean deviation: {result['mean_score_deviation']:.4f}.")
    st.dataframe(df,hide_index=True)
    st.plotly_chart(px.bar(df.groupby('dimension',as_index=False).score_deviation.mean(),x='dimension',y='score_deviation',title='Mean sensitivity by dimension'),width='stretch')
    st.download_button('Download resilience report',json_report(result),'malguard-resilience.json','application/json')


def exposure_page(store,owner):
    page_header('Exposure Simulator')
    explain('Start here: build and read a scenario',
            'Use the labeled example to learn, or download its JSON file and replace the computers and connections with your own inventory. '
            'Choose where the assumed incident starts, then simulate. **Direct exposure** means one connection from that computer; '
            '**secondary exposure** means two or more connections. **Priority score** ranks which computers deserve attention, not their chance of being hacked. '
            'Select computers under **What-if: isolate assets** to see how blocking them changes reachability. No computers are contacted or attacked.')
    st.write('Explore hypothetical blast radius through the directed connections in your environment profile.')
    st.info('This is a generic exposure scenario. A static ML prediction cannot establish malware capabilities or confirm compromise.')
    record = select_scan(store,owner)
    use_example = st.checkbox('Use the clearly labeled example environment',value=False)
    uploaded = st.file_uploader('Infrastructure profile (JSON or YAML)',type=['json','yaml','yml'],key='profile_upload',max_upload_size=1)
    st.download_button('Download example profile',json_report(simulation.EXAMPLE),'example-environment.json','application/json')
    if not use_example and uploaded is None: return
    profile = copy.deepcopy(simulation.EXAMPLE) if use_example else simulation.parse_profile(uploaded.getvalue(),uploaded.name.rsplit('.',1)[-1])
    initial = st.selectbox('Initial exposure point',[h['id'] for h in profile['hosts']])
    windows = st.checkbox('Assume Windows-only exposure',value=True)
    isolated = st.multiselect('What-if: isolate assets',[h['id'] for h in profile['hosts']])
    signature = json_report([profile,initial,windows,isolated,record['sha256'] if record else None])
    if st.session_state.get('exposure_signature') != signature: st.session_state.pop('exposure_result',None)
    if st.button('Simulate exposure',type='primary'):
        with st.spinner('Evaluating supplied graph relationships…'):
            baseline = simulation.simulate(profile,initial,windows,scan=record)
            result = simulation.simulate(profile,initial,windows,isolated,record)
            result['baseline_exposed'] = baseline['exposed']
            store.save_experiment(owner,record['scan_id'] if record else '',result)
            st.session_state['exposure_result'] = result; st.session_state['exposure_signature'] = signature
    result = st.session_state.get('exposure_result')
    if not result: return
    a,b,c,d = st.columns(4)
    a.metric('Modeled assets',result['total']); b.metric('Potentially exposed',result['exposed'],result['exposed']-result['baseline_exposed'],delta_color='inverse')
    c.metric('Direct exposure',result['direct']); d.metric('Secondary exposure',result['secondary'])
    try:
        components.html(simulation.graph_html(profile,result),height=540,scrolling=False)
    except ImportError:
        st.warning('PyVis is unavailable; the interactive Plotly fallback is shown.')
        import networkx as nx
        g = simulation.graph(profile); pos = nx.spring_layout(g,seed=42)
        fig = go.Figure()
        for u,v in g.edges:
            fig.add_trace(go.Scatter(x=[pos[u][0],pos[v][0]],y=[pos[u][1],pos[v][1]],mode='lines',showlegend=False))
        fig.add_trace(go.Scatter(x=[pos[n][0] for n in g],y=[pos[n][1] for n in g],text=list(g),mode='markers+text',showlegend=False))
        st.plotly_chart(fig,width='stretch')
    st.caption('Deep blue: starting computer · Dark pink: high priority · Bubblegum pink: reachable · Gray: protected or unreachable. Pan, zoom and hover for details; the table also labels every status.')
    st.dataframe(pd.DataFrame(result['assets']),hide_index=True)
    st.subheader('Conceptual kill chain')
    st.dataframe(pd.DataFrame(result['kill_chain']),hide_index=True)
    st.caption(result['limitations'])
    with st.expander('Scoring rules and scenario assumptions'):
        st.write('Reachable score = clamp(20 + 12 × criticality + min(20, 5 × services) − 15 for endpoint protection − 10 for least privilege, 0, 100). Unreachable or isolated assets score 0. High priority begins at 70. Scores rank review priorities only.')
        st.json(result['assumptions'])
    st.download_button('Download exposure report',json_report(result),'malguard-exposure.json','application/json')


def history(store,owner):
    page_header('Scan History & Reports')
    selected = filters(store,owner)
    selected['search'] = st.text_input('Search filename or SHA-256',max_chars=120)
    ascending = st.checkbox('Oldest first')
    total = store.summary(owner,selected)['total']
    page = st.number_input('Page (50 records)',1,max(1,(total+49)//50),1)
    try:
        records = store.records(owner,selected,limit=50,offset=(int(page)-1)*50,ascending=ascending)
    except AnalysisError as exc:
        st.error(str(exc))
        st.info('Privacy controls below remain available to delete this workspace history.')
        records = []
    st.caption(f'{total} matching records. Exports below contain this page only.')
    if records:
        st.dataframe(pd.DataFrame(records)[['timestamp','filename','sha256','verdict','risk','model_version']],hide_index=True)
        a,b = st.columns(2)
        a.download_button('Export page JSON',json_report(records),'malguard-history.json','application/json')
        b.download_button('Export page CSV',csv_report(records),'malguard-history.csv','text/csv')
        index = st.selectbox('Individual scan',range(len(records)),format_func=lambda i: records[i]['filename']+' · '+records[i]['sha256'][:12])
        with st.expander('Scan details and report'): _result(records[index])
        compared = st.multiselect('Compare up to two scans',range(len(records)),format_func=lambda i:records[i]['filename']+' · '+records[i]['scan_id'][:8],max_selections=2)
        if len(compared) == 2:
            rows = [records[i] for i in compared]
            if rows[0]['model_version'] != rows[1]['model_version']:
                st.warning('Different model versions: compare verdicts and observations; their uncalibrated scores are not directly comparable.')
            st.dataframe(pd.DataFrame(rows)[['filename','sha256','model_version','verdict','entropy','size']],hide_index=True)
        if st.checkbox('Confirm deletion of selected scan and its experiments') and st.button('Delete selected scan'):
            store.delete(owner,records[index]['scan_id']); st.session_state.pop('active_scan',None); st.session_state.pop('scan_results',None); st.rerun()
    else: st.info('No matching history records.')
    with st.expander('Privacy and retention'):
        days = st.number_input('Retention days',1,3650,st.session_state.get('retention_days',30))
        st.caption('The administrator-configured retention is applied automatically. This action shortens retention for this workspace only.')
        if st.button('Delete older records from this workspace'):
            cutoff = (datetime.now(timezone.utc)-timedelta(days=int(days))).isoformat()
            # Bounded deletion batches; each request removes up to 1,000 records.
            old = store.records(owner,{'end':cutoff},limit=1000)
            for record in old: store.delete(owner,record['scan_id'])
            st.success(f'Deleted {len(old)} older records. Repeat if more remain.')
        if st.checkbox('Confirm deletion of all records in this workspace') and st.button('Delete workspace history'):
            store.delete(owner)
            for key in ('active_scan','scan_results','resilience_result','exposure_result'): st.session_state.pop(key,None)
            st.rerun()
    results = store.experiments(owner)
    if results:
        st.download_button('Export latest 100 scenario reports',json_report(results),'malguard-scenarios.json','application/json')


def model_insights():
    page_header('Model Insights')
    model,manifest = load_model()
    a,b,c = st.columns(3)
    a.metric('Model',manifest['algorithm']); b.metric('Static features',len(manifest['features'])); c.metric('Held-out rows',manifest['test_rows'])
    st.caption('Labels: 0 = malware, 1 = legitimate. Review required is a separate score-based flag.')
    metrics = manifest['test_metrics']
    a,b,c = st.columns(3)
    a.metric('Correct answers in the test',f"{metrics['accuracy']:.2%}")
    b.metric('Malware found in the test',f"{metrics['malware_recall']:.2%}")
    c.metric('Malware F1 score',f"{metrics['malware_f1']:.2%}")
    st.write('These results come from held-out dataset rows: examples not used to fit or choose this model. They describe this evaluation, not every new file you upload.')
    explain('Accuracy, precision, recall and other metrics',
            '**Accuracy** is the share of all test answers that were correct. **Precision** asks how many malware warnings were correct. '
            '**Recall** asks how much of the malware was found. **F1** balances precision and recall. '
            '**False positive rate** measures legitimate files incorrectly flagged; **false negative rate** measures malware missed. '
            '**ROC-AUC and average precision** summarize how well scores separate the classes across thresholds; higher is better on this dataset. '
            'The confusion matrix counts correct and incorrect answers, ordered legitimate then malware. '
            '**Feature importance** shows which file properties the model uses most overall; it does not explain the cause of a specific result.')
    with st.expander('Technical model record and complete evaluation metrics'):
        st.json({k:v for k,v in manifest.items() if k not in ('features','test_examples')})
    st.warning('Scores are uncalibrated. Dataset holdout results are not guarantees for current threats. Family and temporal leakage cannot be ruled out with the supplied data.')
    if hasattr(model,'feature_importances_'):
        df = pd.DataFrame({'feature':manifest['features'],'importance':model.feature_importances_}).nlargest(15,'importance')
        st.plotly_chart(px.bar(df,x='importance',y='feature',orientation='h',title='Global impurity-based feature importance'),width='stretch')
        st.caption('Global model associations; not per-file causal explanations. Impurity importance can favor high-cardinality features.')


def main():
    st.set_page_config(page_title='MalGuard AI',page_icon='🛡️',layout='wide')
    logging.basicConfig(level=logging.WARNING,format='%(levelname)s %(name)s: %(message)s')
    apply_theme()
    try:
        secret_values = read_secrets()
        settings = load_settings(secret_values)
        st.session_state['retention_days'] = settings.retention_days
        if settings.production:
            if not st.user.is_logged_in:
                page_header('Security workspace')
                st.info('Sign in to access your private scan history and security tools.')
                if st.button('Sign in',type='primary'): st.login()
                return
            try: owner = authenticated_owner(st.user.to_dict(),settings.allowed_subjects)
            except AnalysisError as exc:
                st.error(str(exc))
                if st.button('Sign out'): st.logout()
                return
            if st.session_state.get('owner') != owner:
                for key in list(st.session_state):
                    if key not in ('show_animations','retention_days'): del st.session_state[key]
            st.session_state['owner'] = owner
    except AnalysisError as exc:
        st.error(str(exc)); return
    except Exception as exc:
        LOGGER.error('Workspace access failed (%s)',type(exc).__name__)
        st.error('Workspace access could not be established. Check the sign-in and secrets configuration; access is blocked.')
        return
    if 'owner' not in st.session_state: st.session_state['owner'] = secrets.token_urlsafe(32)
    with st.sidebar:
        st.title('MalGuard AI')
        st.caption('INTELLIGENT MALWARE DETECTION\n\nThreat Intelligence & Security Analysis')
        page = st.radio('Workspace',PAGES,key='nav')
        st.checkbox('Show animations',value=True,key='show_animations',help='Decorative illustrations only. They do not show scan progress.')
        st.divider()
        if settings.production:
            st.caption('Signed-in workspace. Your saved history follows your account.')
            if st.button('Sign out'): st.logout()
        else:
            st.caption('Local workspace. This browser session has its own history; sign-in is disabled. New sessions start a new workspace.')
        st.caption('Static evidence • Bounded experiments • No execution')
    try:
        if page == 'File Security':
            file_security(); return
        if page == 'Model Insights':
            model_insights(); return
        store = database(settings.database_url or '')
        store.retain(settings.retention_days)
        owner = st.session_state['owner']
        routes = {'Overview':lambda:overview(store,owner),'Malware Scanner':lambda:scanner_page(store,owner),
            'Threat Intelligence':lambda:intelligence(store,owner),'File Security':file_security,
            'Resilience Lab':lambda:resilience_page(store,owner),'Exposure Simulator':lambda:exposure_page(store,owner),
            'Scan History & Reports':lambda:history(store,owner),'Model Insights':model_insights}
        routes[page]()
    except AnalysisError as exc:
        st.error(str(exc))
    except Exception as exc:
        # Log only the error class: exceptions may contain filenames or DB credentials.
        LOGGER.error('Page operation failed (%s)',type(exc).__name__)
        st.error('This operation could not complete. Check the configured database, model and dependencies; no success has been recorded.')

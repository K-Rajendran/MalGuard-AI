"""Shared brand, plain-language guidance and local decorative animations."""
from functools import lru_cache
import copy
import json
import html
import streamlit as st
import streamlit.components.v1 as components
import plotly.io as pio
import plotly.graph_objects as go
from .core import ROOT

BLUE, WHITE, PINK = '#09318D', '#FFFFFF', '#FD91CC'
GUIDES = {
    'Security workspace': ('Start with a file check, protect a document, or explore a security scenario.', 'malware prevention.json'),
    'Malware Scanner': ('Upload a Windows program or DLL, choose Analyze files, then read the result and recommended next step.', 'virus scanning.json'),
    'Threat Intelligence': ('See patterns in files you have checked. Choose a date range to focus on an investigation.', 'anti virus.json'),
    'File Security': ('Encrypt locks a file with your password. Decrypt opens it again with the same password.', 'encryption.json'),
    'Resilience Lab': ('See whether small changes to file information affect the model’s answer. Your file stays unchanged.', 'virus.json'),
    'Exposure Simulator': ('Describe computers and their connections to explore which could be reachable in an assumed incident.', 'protection.json'),
    'Scan History & Reports': ('Find earlier checks, compare results, download reports, or delete your saved records.', 'anti virus.json'),
    'Model Insights': ('Understand what the detector learned, how it was evaluated, and where its answers can be wrong.', 'protection.json'),
}


def apply_theme():
    pio.templates['malguard'] = go.layout.Template(layout={
        'paper_bgcolor': WHITE, 'plot_bgcolor': WHITE,
        'font': {'color':'#132547','family':'Arial, sans-serif'},
        'colorway':[BLUE,PINK,'#597CC8','#AD397E','#68748B'],
        'xaxis':{'gridcolor':'#E8ECF5'},'yaxis':{'gridcolor':'#E8ECF5'},
    })
    pio.templates.default = 'malguard'
    st.html('''<style>
    .stApp {background:linear-gradient(135deg,#FFFFFF 45%,#FD91CC18 100%);}
    [data-testid="stSidebar"] {background:linear-gradient(165deg,#EAF0FF 0%,#FFFFFF 50%,#FD91CC40 100%);border-right:1px solid #DCE3F4;}
    [data-testid="stMarkdownContainer"] h1,[data-testid="stMarkdownContainer"] h2,[data-testid="stMarkdownContainer"] h3 {color:#09318D;letter-spacing:-.025em;}
    h1 {font-weight:750;}
    [data-testid="stMetric"] {background:linear-gradient(120deg,#FFFFFF,#F1F5FF 70%,#FD91CC25);border:1px solid #DCE3F4;border-top:3px solid #09318D;border-radius:14px;padding:1rem;}
    [data-testid="stMetricValue"] {color:#09318D;}
    [data-testid="stBaseButton-primary"] {background:linear-gradient(110deg,#09318D,#294FA3);border:1px solid #09318D;color:#FFFFFF;}
    [data-testid="stBaseButton-primary"]:hover {box-shadow:0 3px 12px #FD91CC80;border-color:#AD397E;color:#FFFFFF;}
    button:focus-visible,a:focus-visible {outline:3px solid #AD397E!important;outline-offset:3px;}
    .brand-line {height:5px;border-radius:8px;background:linear-gradient(90deg,#09318D,#FD91CC,#FFFFFF);margin-bottom:1.2rem;}
    @media(max-width:640px) {[data-testid="stMetric"] {padding:.7rem;} h1 {font-size:2rem!important;}}
    @media(prefers-reduced-motion:reduce) {* {animation:none!important;transition:none!important;}}
    </style>''')


@lru_cache(maxsize=8)
def animation_html(filename: str) -> str:
    allowed = {value[1] for value in GUIDES.values()} | {'malwaredetected.json'}
    if filename not in allowed: raise ValueError('Unknown illustration')
    data = json.loads((ROOT/'lottiefiles'/filename).read_text(encoding='utf-8'))
    # Recolor only static shape colors in a copy; preserve the original assets.
    data = copy.deepcopy(data)
    def recolor(node):
        if isinstance(node,dict):
            if node.get('ty') in ('fl','st'):
                color = node.get('c',{})
                values = color.get('k',[])
                if isinstance(values,list) and len(values)>=3 and all(isinstance(v,(int,float)) for v in values):
                    level=sum(values[:3])/3
                    chosen = (1,1,1) if level>.92 else ((253/255,145/255,204/255) if level>.45 else (9/255,49/255,141/255))
                    color['k'] = [*chosen, *values[3:]]
            for value in node.values(): recolor(value)
        elif isinstance(node,list):
            for value in node: recolor(value)
    recolor(data)
    player=(ROOT/'malguard/assets/lottie_light.min.js').read_text(encoding='utf-8')
    payload=json.dumps(data).replace('<','\\u003c')
    label=html.escape(filename.removesuffix('.json'))
    return f'''<style>body{{margin:0;font:12px Arial;color:#09318D;background:transparent}}#art{{height:135px}}button{{background:white;color:#09318D;border:1px solid #DCE3F4;border-radius:6px;padding:4px 8px}}button:focus-visible{{outline:2px solid #09318D}}</style>
    <div id="art" role="img" aria-label="Decorative {label} illustration"></div><button id="motion">Pause animation</button>
    <script>{player}</script><script>
    const reduced=matchMedia('(prefers-reduced-motion: reduce)');
    const art=lottie.loadAnimation({{container:document.getElementById('art'),renderer:'svg',loop:true,autoplay:!reduced.matches,animationData:{payload}}});
    let paused=reduced.matches; const button=document.getElementById('motion');
    function setMotion(value){{paused=value;paused?art.pause():art.play();button.textContent=paused?'Play animation':'Pause animation';}}
    art.addEventListener('DOMLoaded',()=>setMotion(paused));
    button.onclick=()=>setMotion(!paused);reduced.addEventListener('change',e=>setMotion(e.matches));
    </script>'''


def page_header(title):
    guidance, asset = GUIDES[title]
    st.html('<div class="brand-line"></div>')
    if st.session_state.get('show_animations',True):
        left,right=st.columns([4,1],vertical_alignment='center')
        with left:
            st.title(title); st.write(guidance)
        with right: components.html(animation_html(asset),height=170)
    else:
        st.title(title); st.write(guidance)


def explain(title, text):
    with st.expander(title): st.markdown(text)

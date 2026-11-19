import json
import tomllib
from malguard.core import ROOT
from malguard.presentation import animation_html, GUIDES


def test_packaged_animations_render_offline_and_respect_motion():
    assets={value[1] for value in GUIDES.values()}|{'malwaredetected.json'}
    for asset in assets:
        original=(ROOT/'lottiefiles'/asset).read_bytes()
        result=animation_html(asset)
        assert 'lottie.loadAnimation' in result and 'prefers-reduced-motion' in result
        assert '<script src=' not in result
        assert original==(ROOT/'lottiefiles'/asset).read_bytes()
        assert json.loads(original)['layers']


def test_release_configuration_uses_single_server_port():
    config=tomllib.loads((ROOT/'.streamlit/config.toml').read_text())
    assert config['global']['developmentMode'] is False
    assert config['server']['port']==8501
    assert config['theme']['primaryColor']=='#09318D'

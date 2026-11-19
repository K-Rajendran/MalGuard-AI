"""Check pinned public package versions against PyPI's published advisories."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def check(line):
    name,version = line.split('==',1)
    request = urllib.request.Request(f'https://pypi.org/pypi/{name}/{version}/json',headers={'User-Agent':'MalGuard-dependency-validation/1'})
    try:
        with urllib.request.urlopen(request,timeout=15) as response: data=json.load(response)
        return {'package':name,'version':version,'vulnerabilities':data.get('vulnerabilities',[])}
    except Exception as exc:
        return {'package':name,'version':version,'error':type(exc).__name__}


if __name__ == '__main__':
    lines=[line.strip() for line in (ROOT/'requirements.txt').read_text().splitlines() if '==' in line and not line.startswith('#')]
    with ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(check,lines))
    output={'checked_at_utc':datetime.now(timezone.utc).isoformat(),'source':'PyPI release JSON vulnerabilities',
            'packages':results,'errors':sum('error' in r for r in results),
            'affected':sum(bool(r.get('vulnerabilities')) for r in results)}
    (ROOT/'.runtime').mkdir(exist_ok=True)
    (ROOT/'.runtime/dependency-audit.json').write_text(json.dumps(output,indent=2))
    print(json.dumps({'packages':len(results),'errors':output['errors'],'affected':output['affected']}))
    for result in results:
        if result.get('error') or result.get('vulnerabilities'): print(json.dumps(result))
    raise SystemExit(1 if output['errors'] or output['affected'] else 0)

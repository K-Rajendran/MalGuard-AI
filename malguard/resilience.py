"""Feature-space sensitivity only: no binary mutation or evasion artifacts."""
import math
import random
from time import monotonic
from .core import AnalysisError
from .ml import predict

# Metadata dimensions do not encode executable instructions or PE layout.
DIMENSIONS = ('MajorLinkerVersion', 'MinorLinkerVersion', 'MajorImageVersion', 'MinorImageVersion',
              'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 'CheckSum')


def evaluate(features: dict, dimensions: list[str], strength: float = .1, count: int = 24, seed: int = 42) -> dict:
    if type(count) is not int or not 1 <= count <= 128 or not math.isfinite(strength) or not 0 < strength <= .5:
        raise AnalysisError('Choose 1–128 scenarios and strength above 0 up to 0.5.')
    if type(seed) is not int or not 0 <= seed <= 2**32-1:
        raise AnalysisError('Seed must be an integer from 0 through 4294967295.')
    if not dimensions or len(dimensions) > len(DIMENSIONS) or len(set(dimensions)) != len(dimensions) or any(d not in DIMENSIONS for d in dimensions):
        raise AnalysisError('Select one or more supported metadata dimensions.')
    baseline = predict(features)
    rng, results, start = random.Random(seed), [], monotonic()
    for i in range(count):
        if monotonic() - start > 15:
            raise AnalysisError('Scenario evaluation exceeded 15 seconds; reduce the scenario count.')
        dimension = dimensions[i % len(dimensions)]
        variant = dict(features)
        before = features[dimension]
        change = max(1, round(max(before, 1) * strength)) * rng.choice((-1, 1))
        upper = 2**32 - 1 if dimension == 'CheckSum' else (255 if 'Linker' in dimension else 65535)
        variant[dimension] = max(0, min(upper, round(before + change)))
        if variant[dimension] == before:
            variant[dimension] = max(0, min(upper, round(before - change)))
        result = predict(variant)
        results.append({'scenario': i+1, 'dimension': dimension, 'before': before, 'after': variant[dimension],
                        'verdict': result['verdict'], 'malware_score': result['malware_score'],
                        'score_deviation': abs(result['malware_score']-baseline['malware_score']),
                        'stable': result['label'] == baseline['label']})
    stable = sum(r['stable'] for r in results)
    return {'kind': 'feature_sensitivity', 'baseline': baseline, 'scenarios': results, 'seed': seed, 'strength': strength,
            'stable': stable, 'flips': count-stable, 'count': count, 'stability_percent': 100*stable/count,
            'max_score_deviation': max(r['score_deviation'] for r in results),
            'mean_score_deviation': sum(r['score_deviation'] for r in results)/count,
            'interpretation': 'Stable' if stable == count else ('Moderately sensitive' if stable/count >= .8 else 'Highly sensitive'),
            'limitation': 'Bounded synthetic metadata sensitivity; these vectors are not actual files. No universal robustness or bypass conclusion.'}

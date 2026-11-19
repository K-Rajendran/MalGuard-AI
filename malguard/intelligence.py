"""Calendar aggregation of actual daily scan counts returned by storage."""
import pandas as pd
from .core import AnalysisError


def trend_counts(rows: list[dict], interval: str) -> pd.DataFrame:
    frequencies = {'Daily': 'D', 'Weekly': 'W-SUN', 'Monthly': 'MS'}
    if interval not in frequencies:
        raise AnalysisError('Choose a daily, weekly or monthly trend interval.')
    if not rows:
        return pd.DataFrame(columns=['day', 'verdict', 'count'])
    frame = pd.DataFrame(rows)
    frame['day'] = pd.to_datetime(frame['day'], utc=True)
    return frame.groupby([pd.Grouper(key='day', freq=frequencies[interval]), 'verdict'])['count'].sum().reset_index()

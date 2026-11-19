from malguard.intelligence import trend_counts


def test_calendar_trends_and_empty_history():
    rows=[{'day':date,'verdict':verdict,'count':count} for date,verdict,count in [
        ('2026-01-31','Malware',2),('2026-02-01','Malware',3),('2026-02-02','Legitimate',4)]]
    daily=trend_counts(rows,'Daily')
    weekly=trend_counts(rows,'Weekly')
    monthly=trend_counts(rows,'Monthly')
    assert daily['count'].sum()==weekly['count'].sum()==monthly['count'].sum()==9
    assert weekly[weekly.verdict=='Malware']['count'].tolist()==[5]
    assert monthly[monthly.verdict=='Malware']['count'].tolist()==[2,3]
    assert trend_counts([],'Daily').empty

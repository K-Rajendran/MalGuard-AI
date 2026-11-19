"""Portable exports; CSV cells are protected against formula injection."""
import csv
import io
import json


def json_report(data) -> str:
    return json.dumps(data, indent=2, ensure_ascii=True, allow_nan=False)


def csv_report(records: list[dict]) -> str:
    columns = ['scan_id','timestamp','filename','sha256','format','size','verdict','risk','review','malware_score','model_version','duration_ms']
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, columns, extrasaction='ignore')
    writer.writeheader()
    for record in records:
        values = {}
        for key in columns:
            value = record.get(key, '')
            if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')):
                value = "'" + value
            values[key] = value
        writer.writerow(values)
    return stream.getvalue()


def summary(record: dict) -> str:
    return (f"MalGuard AI investigation\nFile: {record['filename']}\nSHA-256: {record['sha256']}\n"
            f"Observed format: {record['format']} | Size: {record['size']} bytes\n"
            f"Model prediction: {record['verdict']} | Uncalibrated malware score: {record['malware_score']:.4f}\n"
            f"Review required: {record['review']} | Model: {record['model_version']}\n"
            f"UTC: {record['timestamp']}\n{record['score_interpretation']}\n{record['follow_up']}\n"
            'Observations: ' + '; '.join(record['observations']))

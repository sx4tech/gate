"""Bounded, repeatable payload measurements; runner results are not client RTT."""
import ipaddress
import json
import os
import socket
import statistics
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROBE = ROOT / 'tools' / 'perf_probe.mjs'


def probe(mode, host, port, **options):
    payload = {'mode': mode, 'host': host, 'port': port, **options}
    try:
        completed = subprocess.run(['node', str(PROBE)], input=json.dumps(payload),
            capture_output=True, text=True, timeout=40, check=True)
        result = json.loads(completed.stdout)
        return result if isinstance(result, dict) else {'ok': False, 'error': 'Invalid probe result'}
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return {'ok': False, 'error': type(error).__name__}


def summarize_samples(samples):
    """All samples must succeed; use the slower measured throughput for admission."""
    if not samples or any(not s.get('ok') for s in samples):
        return None
    speeds = [s.get('download_mbps') for s in samples]
    first = [s.get('ttfb_ms') for s in samples]
    if any(not isinstance(x, (int, float)) or not 0 < x < 1_000_000 for x in speeds):
        return None
    if any(not isinstance(x, (int, float)) or x < 0 for x in first):
        return None
    return {'download_mbps': round(min(speeds), 2),
        'median_mbps': round(statistics.median(speeds), 2),
        'ttfb_ms': round(statistics.median(first)),
        'jitter_ms': round(max(first) - min(first)), 'samples': samples}


def split_endpoint(value):
    text = value.split('#', 1)[0].strip()
    if text.startswith('['):
        end = text.index(']')
        return text[1:end], int(text[end + 2:]) if text[end + 1:].startswith(':') else 443
    if text.count(':') == 1:
        host, port = text.rsplit(':', 1)
        return host, int(port)
    return text, 443


def resolve_entries(endpoints, max_candidates=24):
    found = []
    for endpoint in endpoints:
        try:
            host, port = split_endpoint(endpoint)
            if not 1 <= port <= 65535:
                continue
            try:
                addresses = [str(ipaddress.ip_address(host))]
            except ValueError:
                addresses = [x[4][0] for x in socket.getaddrinfo(host, port,
                    family=socket.AF_INET, type=socket.SOCK_STREAM)]
            for ip in addresses:
                address = ipaddress.ip_address(ip)
                if not address.is_global or address.version != 4:
                    continue
                pair = (ip, port)
                if pair not in found:
                    found.append(pair)
                if len(found) >= max_candidates:
                    return found
        except (OSError, ValueError):
            continue
    return found


def measure_entries(endpoints, hostname, probe_fn=probe):
    limit = int(os.environ.get('ENTRY_MAX_CANDIDATES', '24'))
    candidates = resolve_entries(endpoints, limit)
    passing = []
    records = []
    max_latency = float(os.environ.get('ENTRY_MAX_LATENCY_MS', '800'))
    min_speed = float(os.environ.get('ENTRY_MIN_MBPS', '10'))
    payload_bytes = int(os.environ.get('SPEED_TEST_BYTES', '2097152'))
    for ip, port in candidates:
        record = {'endpoint': f'{ip}:{port}'}
        latency_samples = [probe_fn('entry-latency', ip, port,
            servername=hostname, timeout_ms=6000) for _ in range(3)]
        record['latency_samples'] = latency_samples
        successful = [x.get('latency_ms') for x in latency_samples if x.get('ok')]
        if len(successful) != 3 or max(successful) > max_latency:
            record['rejection'] = 'https_latency_or_reliability'
            print(f'[ENTRY] {ip}:{port} rejected: latency/reliability {latency_samples}', flush=True)
            records.append(record)
            continue
        samples = []
        for _ in range(2):
            sample = probe_fn('entry-speed', ip, port, bytes=payload_bytes, timeout_ms=15000)
            samples.append(sample)
            if not sample.get('ok') or sample.get('download_mbps', 0) < min_speed:
                break
        summary = summarize_samples(samples) if len(samples) == 2 else None
        if not summary or summary['download_mbps'] < min_speed:
            record['rejection'] = 'download_failed_or_below_minimum'
            record['speed_samples'] = samples
        else:
            record.update(summary)
            record['https_latency_ms'] = round(statistics.median(successful))
            record['colo'] = latency_samples[-1].get('colo')
            passing.append(record)
        records.append(record)
        print(f'[ENTRY] {ip}:{port}: {record}', flush=True)
    passing.sort(key=lambda r: (r['https_latency_ms'] / 200 + 10 / r['download_mbps'],
        -r['download_mbps'], r['endpoint']))
    return passing[:3], records


def select_exits(results, probe_fn=probe):
    candidates = [r for r in results if r.get('success')]
    candidates.sort(key=lambda n: (n.get('latency_ms', 1e9),
        -n.get('source_speed_mbps', 0), n['host']))
    maximum = int(os.environ.get('SPEED_MAX_CANDIDATES', '12'))
    min_speed = float(os.environ.get('EXIT_MIN_MBPS', '10'))
    max_ttfb = float(os.environ.get('EXIT_MAX_TTFB_MS', '1500'))
    max_jitter = float(os.environ.get('EXIT_MAX_JITTER_MS', '500'))
    bytes_count = int(os.environ.get('SPEED_TEST_BYTES', '2097152'))
    passing, records = [], []
    for node in candidates[:maximum]:
        samples = []
        for _ in range(2):
            sample = probe_fn('sstp', node['host'], node['port'],
                bytes=bytes_count, timeout_ms=20000)
            samples.append(sample)
            if not sample.get('ok') or sample.get('download_mbps', 0) < min_speed:
                break
        summary = summarize_samples(samples) if len(samples) == 2 else None
        record = {'host': node['host'], 'port': node['port'], 'samples': samples}
        if (summary and summary['download_mbps'] >= min_speed
                and summary['ttfb_ms'] <= max_ttfb and summary['jitter_ms'] <= max_jitter):
            chosen = dict(node, performance=summary)
            passing.append(chosen)
            record['accepted'] = True
        else:
            record['accepted'] = False
        records.append(record)
        print(f'[EXIT] {node["host"]}:{node["port"]}: {record}', flush=True)
    passing.sort(key=lambda n: (n['performance']['ttfb_ms'] / 500 +
        10 / n['performance']['download_mbps'], -n['performance']['download_mbps'], n['host']))
    selected, counts = [], {}
    for node in passing:
        country = node.get('country_code') or '?'
        if counts.get(country, 0) >= 3:
            continue
        selected.append(node)
        counts[country] = counts.get(country, 0) + 1
        if len(selected) >= int(os.environ.get('MAX_SELECTED_NODES', '6')):
            break
    return selected, records


def performance_select(results, edge_hosts, hostname, probe_fn=probe):
    entries, entry_records = measure_entries(edge_hosts, hostname, probe_fn)
    exits, exit_records = select_exits(results, probe_fn) if entries else ([], [])
    report = {'scope': 'GitHub runner; not the client-to-edgetunnel full path',
        'test_bytes': int(os.environ.get('SPEED_TEST_BYTES', '2097152')),
        'entries': entries, 'entry_tests': entry_records, 'exit_tests': exit_records,
        'exit_candidates': sum(bool(r.get('success')) for r in results),
        'selected_count': len(exits), 'thresholds': {
            'entry_min_mbps': float(os.environ.get('ENTRY_MIN_MBPS', '10')),
            'exit_min_mbps': float(os.environ.get('EXIT_MIN_MBPS', '10')),
            'exit_max_ttfb_ms': float(os.environ.get('EXIT_MAX_TTFB_MS', '1500')),
            'exit_max_jitter_ms': float(os.environ.get('EXIT_MAX_JITTER_MS', '500'))}}
    return exits, [r['endpoint'] for r in entries], report

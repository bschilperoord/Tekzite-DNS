#!/usr/bin/env python3
"""Local-only, bounded load/soak test for a separately spawned Tekzite DNS instance.

Starts a local-only example-zone server on loopback and a chosen unprivileged port.
Never targets an existing DNS service. No network access beyond loopback is needed.
"""
import argparse
import concurrent.futures
import json
import math
import os
from pathlib import Path
import random
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

def percentile(values, fraction):
    if not values:
        return None
    v = sorted(values)
    pos = (len(v) - 1) * fraction
    lo, hi = math.floor(pos), math.ceil(pos)
    return round(v[lo] + (v[hi] - v[lo]) * (pos - lo), 3)

def memory_kb(pid):
    try:
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None

def cpu_seconds(pid):
    try:
        # /proc/<pid>/stat comm is parenthesized and may contain spaces.
        raw = Path(f'/proc/{pid}/stat').read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')
    except (OSError, ValueError, IndexError):
        return None

def query_wire(qid):
    # www.tekzite.test. IN A, no external resolution
    return struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0) + b'\x03www\x07tekzite\x04test\x00\x00\x01\x00\x01'

def run_query(protocol, addr, timeout, qid):
    data = query_wire(qid)
    begin = time.monotonic()
    try:
        if protocol == 'udp':
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(data, addr)
                reply, _ = s.recvfrom(65535)
        else:
            with socket.create_connection(addr, timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(struct.pack('!H', len(data)) + data)
                def recv_exact(n):
                    out = b''
                    while len(out) < n:
                        chunk = s.recv(n - len(out))
                        if not chunk:
                            raise EOFError('TCP response closed early')
                        out += chunk
                    return out
                response_len = struct.unpack('!H', recv_exact(2))[0]
                reply = recv_exact(response_len)
        latency = (time.monotonic() - begin) * 1000
        if len(reply) < 12 or struct.unpack_from('!H', reply)[0] != qid:
            return ('incorrect_response', latency)
        flags = struct.unpack_from('!H', reply, 2)[0]
        if (flags & 0xF) != 0 or not (flags & 0x8000):
            return ('bad_rcode', latency)
        return ('ok', latency)
    except socket.timeout:
        return ('timeout', None)
    except (ConnectionError, OSError, EOFError):
        return ('connection_error', None)

def run(duration, qps, workers, tcp_share, timeout, sample_interval, output):
    if not 1 <= duration <= 86400 or not 1 <= qps <= 2000 or not 1 <= workers <= 128:
        raise ValueError('duration 1..86400 seconds, qps 1..2000, workers 1..128')
    if not 0 <= tcp_share <= 1 or not 0.1 <= timeout <= 30 or sample_interval < 1:
        raise ValueError('invalid tcp-share, timeout, or sample-interval')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='tekzite-rc5-') as temp:
        # Child uses explicitly loopback only. Pick an ephemeral port using a local probe.
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        args = [sys.executable, str(ROOT/'src'/'tekzite_dns.py'), '--zone', str(ROOT/'examples'/'zone.json'),
                '--local-only', '--listen', '127.0.0.1', '--port', str(port),
                '--max-workers', str(max(32, workers * 2))]
        log_path = output/'server.log'
        with log_path.open('w') as log:
            proc = subprocess.Popen(args, cwd=temp, stdout=log, stderr=subprocess.STDOUT)
            try:
                # Confirm readiness with a valid query, not just an open socket.
                for _ in range(100):
                    if proc.poll() is not None:
                        raise RuntimeError(f'server exited early: {proc.returncode}; see server.log')
                    if run_query('udp', ('127.0.0.1', port), 0.2, 1234)[0] == 'ok':
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError('server did not become ready; see server.log')
                started = time.monotonic()
                end = started + duration
                next_request = started
                next_sample = started
                futures = []
                samples = []
                rng = random.Random(0x7E6A17E)
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    while time.monotonic() < end:
                        now = time.monotonic()
                        if now >= next_sample:
                            samples.append({'elapsed_s': round(now-started, 2), 'rss_kb': memory_kb(proc.pid),
                                            'cpu_seconds': cpu_seconds(proc.pid), 'threads': len(os.listdir(f'/proc/{proc.pid}/task')) if sys.platform.startswith('linux') and Path(f'/proc/{proc.pid}/task').exists() else None})
                            next_sample += sample_interval
                        if now >= next_request:
                            protocol = 'tcp' if rng.random() < tcp_share else 'udp'
                            futures.append(pool.submit(run_query, protocol, ('127.0.0.1', port), timeout, rng.randrange(65536)))
                            next_request += 1/qps
                            # Avoid a huge instantaneous catch-up burst after scheduling stalls.
                            if next_request < now - 1:
                                next_request = now
                        else:
                            time.sleep(min(0.01, next_request - now, end - now))
                    results = [f.result() for f in futures]
                samples.append({'elapsed_s': round(time.monotonic()-started, 2), 'rss_kb': memory_kb(proc.pid), 'cpu_seconds': cpu_seconds(proc.pid)})
                statuses = {key: sum(s==key for s, _ in results) for key in ['ok','timeout','connection_error','incorrect_response','bad_rcode']}
                latencies = [lat for status, lat in results if status=='ok' and lat is not None]
                report = {'scenario':'isolated-local-only-example-zone', 'duration_requested_s':duration, 'qps_target':qps,
                          'workers':workers, 'tcp_share':tcp_share, 'requests':len(results), 'statuses':statuses,
                          'success_pct':round(100*statuses['ok']/len(results), 3) if results else 0,
                          'latency_ms':{'p50':percentile(latencies,.5), 'p95':percentile(latencies,.95),
                                        'p99':percentile(latencies,.99), 'max':round(max(latencies),3) if latencies else None},
                          'samples':samples, 'limitations':['No real WAN recursion, RPZ feeds or SQLite cache used',
                                   'Short localhost results cannot predict 24-hour stability',
                                   'CPU/RSS samples are Linux /proc-dependent; no extrapolated production SLA']}
                (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
                (output/'samples.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in samples))
                return report
            finally:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--duration', type=int, default=60, help='Seconds, maximum 86400')
    p.add_argument('--qps', type=int, default=20, help='Target queries/sec, maximum 2000')
    p.add_argument('--workers', type=int, default=8)
    p.add_argument('--tcp-share', type=float, default=.1)
    p.add_argument('--timeout', type=float, default=2.)
    p.add_argument('--sample-interval', type=float, default=5.)
    p.add_argument('--output', default='soak-results')
    args = p.parse_args()
    report = run(args.duration,args.qps,args.workers,args.tcp_share,args.timeout,args.sample_interval,args.output)
    print(json.dumps({k:v for k,v in report.items() if k!='samples'},indent=2))
    if report['statuses']['ok'] != report['requests']:
        sys.exit(1)
if __name__ == '__main__':
    main()

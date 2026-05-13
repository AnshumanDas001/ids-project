"""
server.py — Flask REST API + SocketIO for real-time dashboard
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit

from api.database import (
    get_alerts, get_recent_packets, get_packet_stats,
    get_top_ips, get_alert_counts_by_type, get_total_alerts, clear_all, init_db
)
from sniffer.capture import (
    start_capture, recent_packets, recent_alerts,
    packet_counter, register_alert_callback, register_packet_callback
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-secret-key'
CORS(app, resources={r"/api/*": {"origins": "*"}})

socketio = SocketIO(app, cors_allowed_origins="*",
                    async_mode='threading', logger=False,
                    engineio_logger=False)

# ── SocketIO live-push callbacks ──────────────────────────────────────────────

def push_alert(alert):
    socketio.emit('new_alert', alert)


def push_packet(parsed):
    # Only push a lightweight summary to avoid flooding the websocket
    socketio.emit('new_packet', {
        'src_ip':   parsed.get('src_ip'),
        'dst_ip':   parsed.get('dst_ip'),
        'protocol': parsed.get('protocol'),
        'dst_port': parsed.get('dst_port'),
        'size':     parsed.get('size'),
        'ts':       datetime.utcnow().isoformat(),
    })


register_alert_callback(push_alert)
register_packet_callback(push_packet)


# ── REST endpoints ────────────────────────────────────────────────────────────

@app.route('/api/status')
def status():
    return jsonify({
        'status':  'running',
        'packets': packet_counter.copy(),
        'time':    datetime.utcnow().isoformat(),
    })


@app.route('/api/alerts')
def alerts():
    limit    = int(request.args.get('limit', 100))
    severity = request.args.get('severity')
    data     = get_alerts(limit=limit, severity=severity)
    return jsonify(data)


@app.route('/api/packets')
def packets():
    limit = int(request.args.get('limit', 100))
    data  = get_recent_packets(limit=limit)
    return jsonify(data)


@app.route('/api/stats')
def stats():
    return jsonify({
        'packet_stats':     get_packet_stats(),
        'top_ips':          get_top_ips(10),
        'alert_breakdown':  get_alert_counts_by_type(),
        'live_counters':    packet_counter.copy(),
        'total_alerts':     get_total_alerts(),
    })


@app.route('/api/clear', methods=['POST'])
def clear():
    clear_all()
    # Also clear in-memory deques
    recent_packets.clear()
    recent_alerts.clear()
    for k in packet_counter:
        packet_counter[k] = 0
    return jsonify({'status': 'cleared'})


# ── SocketIO events ───────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    emit('connected', {'msg': 'IDS server connected'})


@socketio.on('request_stats')
def on_stats():
    emit('stats_update', {
        'packet_stats':  get_packet_stats(),
        'top_ips':       get_top_ips(10),
        'live_counters': packet_counter.copy(),
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='IDS Server')
    parser.add_argument('--demo',      action='store_true', help='Run in demo/simulation mode')
    parser.add_argument('--interface', default=None,        help='Network interface to sniff')
    parser.add_argument('--port',      type=int, default=5000)
    args = parser.parse_args()

    init_db()
    start_capture(interface=args.interface, demo=args.demo)

    print(f"\n{'='*50}")
    print(f"  IDS Server running on http://localhost:{args.port}")
    print(f"  Demo mode: {args.demo}")
    print(f"  Interface: {args.interface or 'default'}")
    print(f"{'='*50}\n")

    socketio.run(app, host='0.0.0.0', port=args.port,
                 debug=False, use_reloader=False)
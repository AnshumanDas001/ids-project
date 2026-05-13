"""
database.py — SQLite manager for IDS alerts and packet logs
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'ids.db')


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_conn()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            alert_type  TEXT    NOT NULL,
            severity    TEXT    NOT NULL DEFAULT 'MEDIUM',
            src_ip      TEXT,
            dst_ip      TEXT,
            protocol    TEXT,
            detail      TEXT,
            raw_data    TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT,
            dst_ip      TEXT,
            protocol    TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            size        INTEGER,
            flags       TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            total_packets INTEGER DEFAULT 0,
            tcp_count   INTEGER DEFAULT 0,
            udp_count   INTEGER DEFAULT 0,
            icmp_count  INTEGER DEFAULT 0,
            other_count INTEGER DEFAULT 0
        )
    ''')

    conn.commit()
    conn.close()
    print(f"[DB] Initialized at {DB_PATH}")


def insert_alert(alert_type, severity, src_ip=None, dst_ip=None,
                 protocol=None, detail=None, raw_data=None):
    conn = get_conn()
    c = conn.cursor()
    c.execute('''
        INSERT INTO alerts (timestamp, alert_type, severity, src_ip, dst_ip, protocol, detail, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.utcnow().isoformat(),
        alert_type,
        severity,
        src_ip,
        dst_ip,
        protocol,
        detail,
        json.dumps(raw_data) if raw_data else None
    ))
    conn.commit()
    alert_id = c.lastrowid
    conn.close()
    return alert_id


def insert_packet(src_ip, dst_ip, protocol, src_port=None,
                  dst_port=None, size=0, flags=None):
    conn = get_conn()
    c = conn.cursor()
    c.execute('''
        INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, flags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.utcnow().isoformat(),
        src_ip, dst_ip, protocol, src_port, dst_port, size, flags
    ))
    conn.commit()
    conn.close()


def get_alerts(limit=100, severity=None):
    conn = get_conn()
    c = conn.cursor()
    if severity:
        c.execute('SELECT * FROM alerts WHERE severity=? ORDER BY id DESC LIMIT ?',
                  (severity, limit))
    else:
        c.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_recent_packets(limit=200):
    conn = get_conn()
    c = conn.cursor()
    c.execute('SELECT * FROM packets ORDER BY id DESC LIMIT ?', (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_packet_stats():
    conn = get_conn()
    c = conn.cursor()
    c.execute('''
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN protocol='TCP'  THEN 1 ELSE 0 END) as tcp,
            SUM(CASE WHEN protocol='UDP'  THEN 1 ELSE 0 END) as udp,
            SUM(CASE WHEN protocol='ICMP' THEN 1 ELSE 0 END) as icmp,
            SUM(CASE WHEN protocol NOT IN ('TCP','UDP','ICMP') THEN 1 ELSE 0 END) as other
        FROM packets
    ''')
    row = dict(c.fetchone())
    conn.close()
    return row


def get_top_ips(limit=10):
    conn = get_conn()
    c = conn.cursor()
    c.execute('''
        SELECT src_ip, COUNT(*) as count
        FROM packets
        WHERE src_ip IS NOT NULL
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT ?
    ''', (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_alert_counts_by_type():
    conn = get_conn()
    c = conn.cursor()
    c.execute('''
        SELECT alert_type, severity, COUNT(*) as count
        FROM alerts
        GROUP BY alert_type, severity
        ORDER BY count DESC
    ''')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_total_alerts():
    conn = get_conn()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) as total FROM alerts')
    row = dict(c.fetchone())
    conn.close()
    return row['total']


def clear_all():
    conn = get_conn()
    c = conn.cursor()
    c.execute('DELETE FROM alerts')
    c.execute('DELETE FROM packets')
    conn.commit()
    conn.close()
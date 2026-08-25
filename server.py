import json
import random
import sqlite3
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "cyber_dashboard.db"
INDEX_PATH = ROOT / "index.html"

random.seed(42)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_date TEXT NOT NULL,
            region TEXT NOT NULL,
            sector TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            attack_vector TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            owner TEXT NOT NULL,
            affected_assets INTEGER NOT NULL,
            response_time_hours REAL NOT NULL,
            cost_usd REAL NOT NULL,
            detection_source TEXT NOT NULL
        )
        """
    )

    existing = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    if not existing:
        seed_data(conn)

    conn.commit()
    conn.close()


def seed_data(conn):
    regions = ["Sul", "Sudeste", "Nordeste", "Norte", "Centro-Oeste"]
    sectors = [
        "Financeiro",
        "Saúde",
        "Varejo",
        "Educação",
        "Industria",
        "Logística",
        "Tecnologia",
    ]
    threat_types = [
        "Ransomware",
        "Phishing",
        "DDoS",
        "Malware",
        "Credential Stuffing",
        "Exfiltration",
        "Zero-Day",
    ]
    attack_vectors = [
        "Email Phishing",
        "Malware em endpoint",
        "Botnet DDoS",
        "Exploit de API",
        "Credenciais vazadas",
        "VPN exposta",
        "Drive-by download",
    ]
    severities = ["Baixa", "Média", "Alta", "Crítica"]
    statuses = ["Mitigado", "Em investigação", "Contido", "Reaberto"]
    owners = ["SOC", "CSIRT", "Infraestrutura", "Resposta", "Governança"]
    detection_sources = ["EDR", "SIEM", "Firewall", "Proxy", "IAM", "NDR"]

    start_date = datetime(2025, 1, 1)
    end_date = datetime(2026, 8, 1)

    for idx in range(240):
        event_date = start_date + timedelta(days=random.randint(0, (end_date - start_date).days))
        region = random.choice(regions)
        sector = random.choice(sectors)
        threat_type = random.choice(threat_types)
        attack_vector = random.choice(attack_vectors)
        severity = random.choice(severities)
        status = random.choice(statuses)
        owner = random.choice(owners)
        detection_source = random.choice(detection_sources)
        affected_assets = random.randint(3, 180)
        response_time_hours = round(random.uniform(1.5, 72), 1)
        cost_usd = round(random.uniform(12000, 280000), 2)
        source_ip = f"{random.randint(10, 210)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

        conn.execute(
            """
            INSERT INTO incidents (
                event_date, region, sector, threat_type, attack_vector,
                severity, status, source_ip, owner, affected_assets,
                response_time_hours, cost_usd, detection_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_date.strftime("%Y-%m-%d"),
                region,
                sector,
                threat_type,
                attack_vector,
                severity,
                status,
                source_ip,
                owner,
                affected_assets,
                response_time_hours,
                cost_usd,
                detection_source,
            ),
        )


def fetch_dashboard_data(filters=None):
    filters = filters or {}
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    where_clauses = []
    params = []

    if filters.get("sector") and filters["sector"] != "all":
        where_clauses.append("sector = ?")
        params.append(filters["sector"])

    if filters.get("severity") and filters["severity"] != "all":
        where_clauses.append("severity = ?")
        params.append(filters["severity"])

    if filters.get("region") and filters["region"] != "all":
        where_clauses.append("region = ?")
        params.append(filters["region"])

    sql_where = " AND ".join(where_clauses)
    if sql_where:
        sql_where = "WHERE " + sql_where
    else:
        sql_where = ""

    total = conn.execute(
        f"SELECT COUNT(*) AS total, ROUND(AVG(cost_usd), 2) AS avg_cost, ROUND(AVG(response_time_hours), 1) AS mttr, ROUND(AVG(affected_assets), 1) AS avg_assets FROM incidents {sql_where}",
        params,
    ).fetchone()

    critical_share = conn.execute(
        f"SELECT ROUND(100.0 * SUM(CASE WHEN severity = 'Crítica' THEN 1 ELSE 0 END) / COUNT(*), 1) AS critical_share FROM incidents {sql_where}",
        params,
    ).fetchone()

    sla = conn.execute(
        f"SELECT ROUND(100.0 * SUM(CASE WHEN response_time_hours <= 24 THEN 1 ELSE 0 END) / COUNT(*), 1) AS sla FROM incidents {sql_where}",
        params,
    ).fetchone()

    monthly = conn.execute(
        f"""
        SELECT strftime('%Y-%m', event_date) AS month,
               COUNT(*) AS incidents,
               ROUND(AVG(cost_usd), 2) AS total_cost
        FROM incidents {sql_where}
        GROUP BY strftime('%Y-%m', event_date)
        ORDER BY month ASC
        """,
        params,
    ).fetchall()

    vectors = conn.execute(
        f"""
        SELECT attack_vector AS name, COUNT(*) AS value
        FROM incidents {sql_where}
        GROUP BY attack_vector
        ORDER BY value DESC, name ASC
        LIMIT 5
        """,
        params,
    ).fetchall()

    severities = conn.execute(
        f"""
        SELECT severity AS name, COUNT(*) AS value
        FROM incidents {sql_where}
        GROUP BY severity
        ORDER BY CASE severity WHEN 'Crítica' THEN 1 WHEN 'Alta' THEN 2 WHEN 'Média' THEN 3 WHEN 'Baixa' THEN 4 END
        """,
        params,
    ).fetchall()

    regions = conn.execute(
        f"""
        SELECT region AS name, COUNT(*) AS value
        FROM incidents {sql_where}
        GROUP BY region
        ORDER BY value DESC
        """,
        params,
    ).fetchall()

    recent = conn.execute(
        f"""
        SELECT event_date, sector, threat_type, severity, region, source_ip, response_time_hours, cost_usd
        FROM incidents {sql_where}
        ORDER BY event_date DESC, id DESC
        LIMIT 8
        """,
        params,
    ).fetchall()

    sectors = conn.execute(
        f"""
        SELECT sector AS name, COUNT(*) AS value
        FROM incidents {sql_where}
        GROUP BY sector
        ORDER BY value DESC
        LIMIT 6
        """,
        params,
    ).fetchall()

    conn.close()

    payload = {
        "totals": {
            "incidents": total["total"] if total else 0,
            "avg_cost": round(float(total["avg_cost"] or 0), 2),
            "mttr": round(float(total["mttr"] or 0), 1),
            "avg_assets": round(float(total["avg_assets"] or 0), 1),
            "critical_share": round(float(critical_share["critical_share"] or 0), 1),
            "sla": round(float(sla["sla"] or 0), 1),
        },
        "monthly": [
            {"month": r["month"], "incidents": r["incidents"], "cost": round(float(r["total_cost"] or 0), 2)}
            for r in monthly
        ],
        "vectors": [{"name": r["name"], "value": r["value"]} for r in vectors],
        "severity": [{"name": r["name"], "value": r["value"]} for r in severities],
        "regions": [{"name": r["name"], "value": r["value"]} for r in regions],
        "sectors": [{"name": r["name"], "value": r["value"]} for r in sectors],
        "recent": [
            {
                "event_date": r["event_date"],
                "sector": r["sector"],
                "threat_type": r["threat_type"],
                "severity": r["severity"],
                "region": r["region"],
                "source_ip": r["source_ip"],
                "response_time_hours": round(float(r["response_time_hours"]), 1),
                "cost_usd": round(float(r["cost_usd"]), 2),
            }
            for r in recent
        ],
    }
    return payload


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/dashboard":
            filters = {
                "sector": query.get("sector", ["all"])[0],
                "severity": query.get("severity", ["all"])[0],
                "region": query.get("region", ["all"])[0],
            }
            payload = fetch_dashboard_data(filters)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        if path in ("/", "/index.html"):
            content = INDEX_PATH.read_text(encoding="utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
            return

        if path.startswith("/static/"):
            file_path = ROOT / path.lstrip("/")
            if file_path.exists() and file_path.is_file():
                content = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/css; charset=utf-8" if file_path.suffix == ".css" else "application/javascript; charset=utf-8")
                self.end_headers()
                self.wfile.write(content)
                return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    init_db()
    server = HTTPServer(("0.0.0.0", 8000), DashboardHandler)
    print("Dashboard de cibersegurança rodando em http://localhost:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")
    finally:
        server.server_close()

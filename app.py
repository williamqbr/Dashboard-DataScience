import random
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "cyber_dashboard.db"

random.seed(42)


@st.cache_resource
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

    rows = []
    for _ in range(240):
        event_date = start_date + timedelta(days=random.randint(0, (end_date - start_date).days))
        rows.append(
            (
                event_date.strftime("%Y-%m-%d"),
                random.choice(regions),
                random.choice(sectors),
                random.choice(threat_types),
                random.choice(attack_vectors),
                random.choice(severities),
                random.choice(statuses),
                f"{random.randint(10, 210)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                random.choice(owners),
                random.randint(3, 180),
                round(random.uniform(1.5, 72), 1),
                round(random.uniform(12000, 280000), 2),
                random.choice(detection_sources),
            )
        )

    conn.executemany(
        """
        INSERT INTO incidents (
            event_date, region, sector, threat_type, attack_vector,
            severity, status, source_ip, owner, affected_assets,
            response_time_hours, cost_usd, detection_source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()


@st.cache_data
def load_incidents(sector='all', severity='all', region='all'):
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT * FROM incidents"
    filters = []
    params = []

    if sector != 'all':
        filters.append("sector = ?")
        params.append(sector)
    if severity != 'all':
        filters.append("severity = ?")
        params.append(severity)
    if region != 'all':
        filters.append("region = ?")
        params.append(region)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    df = pd.read_sql_query(query, conn, params=params)
    conn.close()

    if df.empty:
        return pd.DataFrame(
            columns=[
                "id",
                "event_date",
                "region",
                "sector",
                "threat_type",
                "attack_vector",
                "severity",
                "status",
                "source_ip",
                "owner",
                "affected_assets",
                "response_time_hours",
                "cost_usd",
                "detection_source",
            ]
        )

    df["event_date"] = pd.to_datetime(df["event_date"])
    return df


@st.cache_data
def get_monthly_data(df):
    if df.empty:
        return pd.DataFrame(columns=["month", "incidents"])
    monthly = df.groupby(df["event_date"].dt.to_period("M").astype(str)).size().reset_index(name="incidents")
    monthly.columns = ["month", "incidents"]
    return monthly


@st.cache_data
def get_severity_distribution(df):
    if df.empty:
        return pd.DataFrame({"severity": [], "count": []})
    counts = df["severity"].value_counts().rename_axis("severity").reset_index(name="count")
    return counts[["severity", "count"]]


def build_dashboard(df):
    st.subheader("Painel de segurança operacional")

    metrics = {
        "Incidentes": len(df),
        "Custo médio": round(float(df["cost_usd"].mean()), 2) if not df.empty else 0,
        "MTTR (h)": round(float(df["response_time_hours"].mean()), 1) if not df.empty else 0,
        "Ativos afetados": round(float(df["affected_assets"].mean()), 1) if not df.empty else 0,
        "Críticos (%)": round(float((df["severity"] == "Crítica").mean() * 100), 1) if not df.empty else 0,
        "SLA (%)": round(float((df["response_time_hours"] <= 24).mean() * 100), 1) if not df.empty else 0,
    }

    cols = st.columns(6)
    for col, (label, value) in zip(cols, metrics.items()):
        if label.startswith("Custo"):
            col.metric(label, f"R$ {value:,.2f}")
        elif label.endswith("(%)"):
            col.metric(label, f"{value}%")
        else:
            col.metric(label, value)

    monthly = get_monthly_data(df)
    severity = get_severity_distribution(df)

    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("#### Incidentes por mês")
        if not monthly.empty:
            st.line_chart(monthly.set_index("month"), width="stretch")
        else:
            st.info("Nenhum dado para este filtro.")
    with col2:
        st.markdown("#### Distribuição por severidade")
        if not severity.empty:
            st.bar_chart(severity.set_index("severity"), width="stretch")
        else:
            st.info("Sem dados de severidade.")

    col3, col4, col5 = st.columns(3)
    with col3:
        top_vectors = df["attack_vector"].value_counts().head(5).rename_axis("Vetor").reset_index(name="Quantidade")
        st.markdown("#### Top vetores de ataque")
        if not top_vectors.empty:
            st.bar_chart(top_vectors.set_index("Vetor"), width="stretch")
        else:
            st.info("Sem dados.")
    with col4:
        top_regions = df["region"].value_counts().head(5).rename_axis("Região").reset_index(name="Quantidade")
        st.markdown("#### Regiões com mais eventos")
        if not top_regions.empty:
            st.bar_chart(top_regions.set_index("Região"), width="stretch")
        else:
            st.info("Sem dados.")
    with col5:
        top_sectors = df["sector"].value_counts().head(6).rename_axis("Setor").reset_index(name="Quantidade")
        st.markdown("#### Setores monitorados")
        if not top_sectors.empty:
            st.bar_chart(top_sectors.set_index("Setor"), width="stretch")
        else:
            st.info("Sem dados.")

    st.markdown("#### Eventos recentes")
    recent = df[["event_date", "sector", "threat_type", "severity", "region", "source_ip", "response_time_hours", "cost_usd"]].sort_values("event_date", ascending=False).head(8).copy()
    if not recent.empty:
        recent["event_date"] = recent["event_date"].dt.strftime("%Y-%m-%d")
        st.dataframe(recent, width="stretch", hide_index=True)
    else:
        st.info("Nenhum evento encontrado para o filtro atual.")


def render_about_me():
    st.header("Quem sou eu")
    st.markdown(
        """
        <div style="background: linear-gradient(135deg, #0f172a, #111827); border: 1px solid rgba(148,163,184,0.35); border-radius: 18px; padding: 24px; margin-bottom: 18px;">
            <h3 style="color:#f8fafc; margin: 0 0 10px 0;">Analista de Cibersegurança e Dados</h3>
            <p style="color:#dfe7f3; line-height: 1.8; margin: 0;">
                Profissional com foco em segurança da informação, monitoramento de ameaças,
                análise de incidentes, automação de processos e apoio à tomada de decisão baseada em dados.
                Tenho interesse em conectar tecnologia, risco e governança para fortalecer a proteção
                digital da organização e reduzir impactos operacionais.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(
            """
            <div style="background: #0b1320; border-radius: 16px; padding: 20px; border: 1px solid rgba(148,163,184,0.25);">
                <h4 style="margin-top:0; color:#7dd3fc;">Perfil profissional</h4>
                <ul style="color:#d9e6f2; line-height:2; padding-left: 18px;">
                    <li>Monitoramento e resposta a incidentes</li>
                    <li>Análise de logs e indicadores de risco</li>
                    <li>Governança e controles de segurança</li>
                    <li>Comunicação técnica com áreas de negócio</li>
                    <li>Criação de dashboards e relatórios</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            """
            <div style="background: #0b1320; border-radius: 16px; padding: 20px; border: 1px solid rgba(148,163,184,0.25);">
                <h4 style="margin-top:0; color:#7dd3fc;">Objetivo</h4>
                <p style="color:#d9e6f2; line-height:1.8; margin:0;">
                    Transformar dados de segurança em informações acionáveis para reduzir riscos,
                    otimizar a resposta a incidentes e apoiar decisões estratégicas em proteção digital.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_qualifications():
    st.header("Minhas qualificações")

    sections = {
        "Formação": [
            "Bacharelado em Engenaria de software",
            "Especialização em Segurança da Informação e Governança",
            "Formação complementar em análise de dados e dashboards",
        ],
        "Experiência relevante": [
            "Análise de incidentes e monitoramento de alertas corporativos",
            "Suporte à gestão de vulnerabilidades e conformidade",
            "Construção de dashboards de segurança com indicadores de risco",
            "Participação em projetos de hardening, resposta e automação operacional",
        ],
        "Cursos complementares": [
            "Python para análise de dados",
            "SQL para BI e relatórios",
            "Power BI / dashboards executivos",
            "Redes e segurança de redes",
            "Fundamentos de Threat Hunting e resposta a incidentes",
        ],
    }

    for title, items in sections.items():
        st.markdown(f"### {title}")
        for item in items:
            st.markdown(f"- {item}")


def render_skills():
    st.header("Skills")

    areas = {
        "Competências técnicas": [
            "Python",
            "SQL",
            "Power BI",
            "Java",
            "Spring Boot",
            "Pandas",
            "Linux",
            "Redes",
        ],
        "Ferramentas e plataformas": [
            "Splunk",
            "AWS",
            "Azure",
            "Microsoft 365",
            "Firewall",
            "NDR",
            "Git",
            "Docker",
        ],
        "Soft skills": [
            "Comunicação clara",
            "Raciocínio analítico",
            "Resolução de problemas",
            "Trabalho em equipe",
            "Gestão de tempo",
            "Aprendizado contínuo",
        ],
    }

    cols = st.columns(len(areas))
    for col, (title, skills) in zip(cols, areas.items()):
        with col:
            st.markdown(f"### {title}")
            for skill in skills:
                st.markdown(f"<span style='display:inline-block; background:#0f172a; border:1px solid rgba(148,163,184,0.25); border-radius:999px; padding:7px 12px; margin:4px 0; color:#dfe7f3;'>{skill}</span>", unsafe_allow_html=True)


def main():
    st.set_page_config(page_title="CyberShield Dashboard", layout="wide")
    init_db()

    st.title("CyberShield | Dashboard Profissional em Segurança da Informação")
    st.caption("Framework utilizado: Streamlit | Banco: SQLite | Dados sintéticos de cibersegurança")

    with st.sidebar:
        st.header("Filtros do dashboard")
        sector_options = ["all"] + sorted(load_incidents().get("sector", pd.Series(dtype=str)).dropna().unique().tolist())
        severity_options = ["all", "Baixa", "Média", "Alta", "Crítica"]
        region_options = ["all"] + sorted(load_incidents().get("region", pd.Series(dtype=str)).dropna().unique().tolist())

        sector = st.selectbox("Setor", options=sector_options)
        severity = st.selectbox("Severidade", options=severity_options)
        region = st.selectbox("Região", options=region_options)

    df = load_incidents(sector=sector, severity=severity, region=region)

    tabs = st.tabs(["Dashboard", "Quem sou eu", "Minhas qualificações", "Skills"])

    with tabs[0]:
        build_dashboard(df)
    with tabs[1]:
        render_about_me()
    with tabs[2]:
        render_qualifications()
    with tabs[3]:
        render_skills()


if __name__ == "__main__":
    main()

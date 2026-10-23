"""
app.py – Streamlit dashboard for the Intelligent Security Log Analyzer / Mini-SIEM.

Launch:
    streamlit run app.py        (from inside siem_project/)

Pages / sections
────────────────
  Sidebar   : dataset controls (Load / Reset & Reload), detection rule tuning
  Overview  : KPI cards – total events, total alerts, severity breakdown
  Events    : searchable, filterable table of all stored log events
  Alerts    : filterable alert table with expandable investigation details
"""

import json
import sys
import os

import streamlit as st
import pandas as pd

# ── Allow running from the project root or from inside siem_project/ ─────────
sys.path.insert(0, os.path.dirname(__file__))

import database
import loader

# ─────────────────────────────────────────────────────────────────────────────
# Page config (must be first Streamlit call)
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Mini-SIEM – Security Log Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# DB init (idempotent)
# ─────────────────────────────────────────────────────────────────────────────
database.init_db()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "HIGH":   "#d62728",
    "MEDIUM": "#ff7f0e",
    "LOW":    "#2ca02c",
    "INFO":   "#1f77b4",
}

SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW", "INFO"]


def _severity_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#888888")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.8em;font-weight:bold;">{sev}</span>'
    )


def _kpi_card(label: str, value: int, color: str = "#3b82d4") -> None:
    st.markdown(
        f"""
        <div style="background:#f7f8fa;border:1px solid #e5e7eb;border-radius:8px;
                    padding:16px 20px;text-align:center;">
          <div style="font-size:2rem;font-weight:700;color:{color};">{value}</div>
          <div style="color:#57606a;font-size:0.9rem;">{label}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar – Dataset Controls
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("🔐 Mini-SIEM")
    st.caption("Intelligent Security Log Analyzer")
    st.divider()

    st.subheader("Dataset")
    log_path = st.text_input(
        "Log file path",
        value=loader.DEFAULT_LOG_PATH,
        help="Absolute or relative path to a JSON log file.",
    )

    st.subheader("Detection Settings")
    brute_threshold = st.slider(
        "Brute-force threshold (failures)", min_value=2, max_value=20,
        value=5, step=1,
        help="Minimum failed logins from one IP within the window to raise an alert.",
    )
    brute_window = st.slider(
        "Brute-force window (minutes)", min_value=1, max_value=60,
        value=5, step=1,
        help="Rolling time window for counting failures.",
    )

    st.divider()

    col_load, col_reset = st.columns(2)

    with col_load:
        load_clicked = st.button("⬇ Load Data", use_container_width=True,
                                 help="Load new events (skips duplicates).")
    with col_reset:
        reset_clicked = st.button("♻ Reset & Reload", use_container_width=True,
                                  help="Clear DB and reload from file.")

    if load_clicked:
        with st.spinner("Loading…"):
            res = loader.load_events_from_file(
                path=log_path,
                brute_threshold=brute_threshold,
                brute_window_minutes=brute_window,
            )
        if res.errors:
            for err in res.errors:
                st.error(err)
        st.success(
            f"✔ {res.inserted_events} new events, "
            f"{res.inserted_alerts} new alerts. "
            f"({res.skipped_events} events already present, "
            f"{res.malformed_events} malformed.)"
        )
        st.rerun()

    if reset_clicked:
        with st.spinner("Resetting…"):
            res = loader.reset_and_reload(
                path=log_path,
                brute_threshold=brute_threshold,
                brute_window_minutes=brute_window,
            )
        if res.errors:
            for err in res.errors:
                st.error(err)
        st.success(
            f"♻ Reset complete. {res.inserted_events} events, "
            f"{res.inserted_alerts} alerts loaded."
        )
        st.rerun()

    st.divider()
    st.caption(
        "⚠ All log data is **synthetic** and does not represent real attacks "
        "or real systems."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main content
# ─────────────────────────────────────────────────────────────────────────────

st.title("Intelligent Security Log Analyzer — Mini-SIEM")
st.caption(
    "Synthetic dataset · For demonstration purposes only · "
    "Not connected to any live infrastructure."
)

tab_overview, tab_events, tab_alerts = st.tabs(["📊 Overview", "📋 Events", "🚨 Alerts"])


# ─── Tab 1: Overview ──────────────────────────────────────────────────────────

with tab_overview:
    events_all = database.get_all_events()
    alerts_all = database.get_all_alerts()
    sev_counts = database.severity_counts()

    total_events = len(events_all)
    total_alerts = len(alerts_all)
    high_count   = sev_counts.get("HIGH",   0)
    medium_count = sev_counts.get("MEDIUM", 0)

    if total_events == 0:
        st.info(
            "No data loaded yet.  "
            "Click **⬇ Load Data** in the sidebar to import the sample dataset."
        )
    else:
        st.subheader("Key Metrics")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            _kpi_card("Total Events", total_events, "#3b82d4")
        with c2:
            _kpi_card("Total Alerts", total_alerts, "#ff7f0e")
        with c3:
            _kpi_card("High Severity", high_count, "#d62728")
        with c4:
            _kpi_card("Medium Severity", medium_count, "#ff7f0e")

        st.divider()

        # ── Event type breakdown ──────────────────────────────────────────────
        if events_all:
            df_ev = pd.DataFrame(events_all)
            st.subheader("Event Type Distribution")
            et_counts = df_ev["event_type"].value_counts().reset_index()
            et_counts.columns = ["event_type", "count"]
            st.bar_chart(et_counts.set_index("event_type"))

        # ── Severity breakdown ────────────────────────────────────────────────
        if alerts_all:
            st.subheader("Alert Severity Breakdown")
            df_al = pd.DataFrame(alerts_all)
            sev_df = df_al["severity"].value_counts().reset_index()
            sev_df.columns = ["severity", "count"]
            # Ensure display order
            sev_df["order"] = sev_df["severity"].map(
                {s: i for i, s in enumerate(SEVERITY_ORDER)}
            ).fillna(99)
            sev_df = sev_df.sort_values("order").drop(columns="order")
            st.bar_chart(sev_df.set_index("severity"))

        # ── Top source IPs by failures ────────────────────────────────────────
        if events_all:
            df_ev = pd.DataFrame(events_all)
            failures_df = df_ev[df_ev["event_type"] == "login_failure"]
            if not failures_df.empty:
                st.subheader("Top Source IPs by Login Failures")
                top_ips = (
                    failures_df.groupby("source_ip")
                    .size()
                    .reset_index(name="failures")
                    .sort_values("failures", ascending=False)
                    .head(10)
                )
                st.bar_chart(top_ips.set_index("source_ip"))


# ─── Tab 2: Events ───────────────────────────────────────────────────────────

with tab_events:
    events_all = database.get_all_events()

    if not events_all:
        st.info("No events in the database.  Use **⬇ Load Data** in the sidebar.")
    else:
        df = pd.DataFrame(events_all)

        st.subheader(f"Security Events ({len(df)} total)")

        # Filters
        fc1, fc2, fc3 = st.columns([2, 2, 2])
        with fc1:
            search_term = st.text_input("🔍 Search (message / user / IP)",
                                        placeholder="e.g. admin or 203.0.113.42")
        with fc2:
            event_types = ["All"] + sorted(df["event_type"].unique().tolist())
            selected_type = st.selectbox("Event type", event_types)
        with fc3:
            services = ["All"] + sorted(df["service"].unique().tolist())
            selected_service = st.selectbox("Service", services)

        filtered = df.copy()
        if search_term:
            mask = (
                filtered["message"].str.contains(search_term, case=False, na=False)
                | filtered["user"].str.contains(search_term, case=False, na=False)
                | filtered["source_ip"].str.contains(search_term, case=False, na=False)
            )
            filtered = filtered[mask]
        if selected_type != "All":
            filtered = filtered[filtered["event_type"] == selected_type]
        if selected_service != "All":
            filtered = filtered[filtered["service"] == selected_service]

        st.caption(f"Showing {len(filtered)} of {len(df)} events")
        st.dataframe(
            filtered[["event_id", "timestamp", "source_ip", "user",
                       "event_type", "service", "message"]],
            use_container_width=True,
            hide_index=True,
        )


# ─── Tab 3: Alerts ───────────────────────────────────────────────────────────

with tab_alerts:
    alerts_all = database.get_all_alerts()

    if not alerts_all:
        st.info("No alerts generated yet.  Use **⬇ Load Data** in the sidebar.")
    else:
        df_al = pd.DataFrame(alerts_all)

        st.subheader(f"Security Alerts ({len(df_al)} total)")

        # Severity filter
        fa1, fa2 = st.columns([2, 3])
        with fa1:
            sev_options = ["All"] + [
                s for s in SEVERITY_ORDER if s in df_al["severity"].unique()
            ]
            selected_sev = st.selectbox("Filter by severity", sev_options,
                                        key="alert_sev_filter")
        with fa2:
            ip_search = st.text_input("🔍 Filter by source IP or user",
                                      placeholder="e.g. 203.0.113.42",
                                      key="alert_ip_search")

        filtered_al = df_al.copy()
        if selected_sev != "All":
            filtered_al = filtered_al[filtered_al["severity"] == selected_sev]
        if ip_search:
            mask = (
                filtered_al["source_ip"].str.contains(ip_search, case=False, na=False)
                | filtered_al["user"].str.contains(ip_search, case=False, na=False)
            )
            filtered_al = filtered_al[mask]

        st.caption(f"Showing {len(filtered_al)} of {len(df_al)} alerts")

        # Summary table
        summary_cols = ["alert_id", "created_at", "severity", "rule_name",
                        "source_ip", "user"]
        st.dataframe(
            filtered_al[summary_cols],
            use_container_width=True,
            hide_index=True,
        )

        st.divider()
        st.subheader("🔍 Alert Investigation View")
        st.caption("Select an alert ID below to inspect its evidence and recommendations.")

        alert_ids = filtered_al["alert_id"].tolist()
        if alert_ids:
            selected_id = st.selectbox("Select alert", alert_ids)
            row = filtered_al[filtered_al["alert_id"] == selected_id].iloc[0]

            sev = row["severity"]
            badge_html = _severity_badge(sev)

            col_a, col_b = st.columns([1, 2])
            with col_a:
                st.markdown(f"**Alert ID:** `{row['alert_id']}`")
                st.markdown(f"**Severity:** {badge_html}", unsafe_allow_html=True)
                st.markdown(f"**Rule:** `{row['rule_name']}`")
                st.markdown(f"**Source IP:** `{row['source_ip']}`")
                st.markdown(f"**User(s):** `{row['user']}`")
                st.markdown(f"**Created at:** `{row['created_at']}`")

            with col_b:
                st.markdown("**Evidence**")
                try:
                    ev_parsed = json.loads(row["evidence"])
                    st.json(ev_parsed)
                except (json.JSONDecodeError, TypeError):
                    st.code(row["evidence"])

            st.markdown("**Recommended Investigation Steps**")
            for line in row["recommendation"].strip().split("\n"):
                st.markdown(line)

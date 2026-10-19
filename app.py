
import streamlit as st
import pandas as pd
import plotly.express as px

from core.database import (
    initialize_database,
    get_security_logs,
    get_security_alerts,
    update_alert_status
)

from core.simulator import (
    simulate_login,
    simulate_brute_force
)


# ---------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------

st.set_page_config(
    page_title="ThreatLens | Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

initialize_database()


# ---------------------------------------
# CUSTOM STYLING
# ---------------------------------------

st.markdown("""
<style>
    .stApp {
        background:
            radial-gradient(circle at 80% -10%, rgba(37, 99, 235, 0.12), transparent 32rem),
            #080d18;
        color: #e5edf8;
    }

    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #111b2d, #0d1524);
        padding: 20px;
        border: 1px solid #22324c;
        border-radius: 14px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.16);
        transition: border-color 160ms ease, transform 160ms ease;
    }

    [data-testid="stMetric"]:hover {
        border-color: #2e8cff;
        transform: translateY(-2px);
    }

    [data-testid="stMetricLabel"] {
        color: #8ea3be;
        font-size: 0.78rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }

    [data-testid="stMetricValue"] {
        color: #f5f9ff;
        font-weight: 700;
    }

    .main-title {
        font-size: clamp(1.8rem, 3vw, 2.6rem);
        font-weight: 700;
        letter-spacing: -0.03em;
        color: #f7fbff;
    }

    .sub-title {
        color: #8ea3be;
        font-size: 0.95rem;
        margin-top: 0.25rem;
    }

    section[data-testid="stSidebar"] {
        background: #0b1322;
        border-right: 1px solid #1d2b42;
    }

    section[data-testid="stSidebar"] h1 {
        color: #f7fbff;
        letter-spacing: 0.08em;
    }

    section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
        color: #8ea3be;
    }

    div[role="radiogroup"] label {
        border-radius: 9px;
        padding: 0.55rem 0.7rem;
        transition: background-color 160ms ease, color 160ms ease;
    }

    div[role="radiogroup"] label:hover {
        background: #15243a;
    }

    div[role="radiogroup"] label p {
        color: #b8c7da;
        font-weight: 500;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #22324c;
        border-radius: 12px;
        overflow: hidden;
    }

    [data-testid="stAlert"] {
        border-radius: 10px;
        border: 1px solid rgba(106, 151, 211, 0.22);
    }

    div[data-testid="stForm"] {
        background: #0e1829;
        border: 1px solid #22324c;
        border-radius: 14px;
        padding: 1rem;
    }

    button[kind="primary"] {
        background: #2563eb;
        border-color: #3b82f6;
    }

    button[kind="primary"]:hover {
        background: #1d4ed8;
        border-color: #60a5fa;
    }

    div.stButton > button {
        border-radius: 9px;
        transition: transform 160ms ease, border-color 160ms ease;
    }

    div.stButton > button:hover {
        border-color: #4b9cff;
        transform: translateY(-1px);
    }

    @media (max-width: 768px) {
        .main-title {
            font-size: 1.8rem;
        }
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------

def load_logs():
    return pd.DataFrame(get_security_logs())


def load_alerts():
    return pd.DataFrame(get_security_alerts())


def show_header(title, description):
    st.markdown(
        f'<div class="main-title">{title}</div>',
        unsafe_allow_html=True
    )
    st.markdown(
        f'<div class="sub-title">{description}</div>',
        unsafe_allow_html=True
    )
    st.divider()


# ---------------------------------------
# SIDEBAR NAVIGATION
# ---------------------------------------

with st.sidebar:

    st.markdown("# 🛡️ THREATLENS")
    st.caption("Security Operations Platform")

    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Dashboard",
            "Log Monitoring",
            "Attack Simulator",
            "Incident Management"
        ]
    )

    st.divider()

    st.markdown("### SYSTEM HEALTH")

    st.success("Database Connected")
    st.success("Detection Engine Active")

    st.caption("ThreatLens v1.0")
    st.caption("Local threat monitoring")


# ---------------------------------------
# LOAD DATA
# ---------------------------------------

logs = load_logs()
alerts = load_alerts()

if not logs.empty:
    logs["timestamp"] = pd.to_datetime(
        logs["timestamp"],
        errors="coerce"
    )

if not alerts.empty:
    alerts["timestamp"] = pd.to_datetime(
        alerts["timestamp"],
        errors="coerce"
    )


# ---------------------------------------
# DASHBOARD
# ---------------------------------------

if page == "Dashboard":

    show_header(
        "ThreatLens Security Operations Center",
        "Monitor security events, threats, and incidents from one command surface."
    )

    if st.button("🔄 Refresh Dashboard"):
        st.rerun()

    total_events = len(logs)

    failed_logins = (
        len(logs[logs["status"] == "FAILED"])
        if not logs.empty else 0
    )

    total_alerts = len(alerts)

    open_alerts = (
        len(alerts[alerts["status"] == "Open"])
        if not alerts.empty else 0
    )

    unique_ips = (
        logs["ip_address"].nunique()
        if not logs.empty else 0
    )

    # METRIC CARDS

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Events", total_events)
    c2.metric("Failed Logins", failed_logins)
    c3.metric("Security Alerts", total_alerts)
    c4.metric("Open Incidents", open_alerts)

    st.write("")

    c5, c6 = st.columns(2)

    c5.metric("Unique IP Addresses", unique_ips)
    c6.metric(
        "Detection Engine",
        "ACTIVE",
        delta="Monitoring enabled"
    )

    st.divider()

    # CHARTS

    st.subheader("Security Analytics")

    chart1, chart2 = st.columns(2)

    with chart1:

        st.markdown("#### Login Activity")

        if not logs.empty:

            login_counts = (
                logs["status"]
                .value_counts()
                .rename_axis("Status")
                .reset_index(name="Count")
            )

            fig = px.pie(
                login_counts,
                names="Status",
                values="Count",
                hole=0.55,
                color="Status",
                color_discrete_map={
                    "SUCCESS": "#16a34a",
                    "FAILED": "#ef4444"
                }
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=20, b=20, l=10, r=10)
            )

            st.plotly_chart(fig, use_container_width=True)

        else:
            st.info("No login events recorded yet.")

    with chart2:

        st.markdown("#### Event Timeline")

        if not logs.empty:

            timeline = (
                logs.dropna(subset=["timestamp"])
                .assign(
                    minute=lambda x:
                    x["timestamp"].dt.floor("min")
                )
                .groupby("minute")
                .size()
                .reset_index(name="Events")
            )

            fig = px.line(
                timeline,
                x="minute",
                y="Events",
                markers=True
            )

            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(t=20, b=20, l=10, r=10)
            )

            st.plotly_chart(fig, use_container_width=True)

        else:
            st.info("No event timeline available.")

    st.divider()

    # RECENT SECURITY EVENTS

    st.subheader("Recent Security Events")

    if not logs.empty:

        display_logs = logs.head(10).copy()

        display_logs["timestamp"] = (
            display_logs["timestamp"]
            .dt.strftime("%Y-%m-%d %H:%M:%S")
        )

        st.dataframe(
            display_logs,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No security events available.")


# ---------------------------------------
# LOG MONITORING
# ---------------------------------------

elif page == "Log Monitoring":

    show_header(
        "Security Log Monitoring",
        "View and analyze recorded security events."
    )

    if st.button("🔄 Refresh Logs"):
        st.rerun()

    logs = load_logs()

    if not logs.empty:

        status_filter = st.selectbox(
            "Filter by Login Status",
            ["ALL", "SUCCESS", "FAILED"]
        )

        ip_filter = st.text_input(
            "Search IP Address",
            placeholder="Enter an IP address..."
        )

        filtered = logs.copy()

        if status_filter != "ALL":
            filtered = filtered[
                filtered["status"] == status_filter
            ]

        if ip_filter.strip():
            filtered = filtered[
                filtered["ip_address"].str.contains(
                    ip_filter.strip(),
                    case=False,
                    na=False
                )
            ]

        st.caption(
            f"Showing {len(filtered)} security events"
        )

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True
        )

        csv_data = filtered.to_csv(index=False).encode("utf-8")

        st.download_button(
            "⬇️ Export Security Logs",
            data=csv_data,
            file_name="siem_security_logs.csv",
            mime="text/csv"
        )

    else:
        st.info("No logs available yet.")


# ---------------------------------------
# ATTACK SIMULATOR
# ---------------------------------------

elif page == "Attack Simulator":

    show_header(
        "Security Event Simulator",
        "Generate controlled login events to test threat detection."
    )

    st.warning(
        "Simulation only. This module generates local test events "
        "and does not attack real accounts or external systems."
    )

    tab1, tab2 = st.tabs([
        "Normal Login Simulation",
        "Brute-Force Simulation"
    ])

    with tab1:

        st.subheader("Simulate Login Attempt")

        with st.form("normal_login_form"):

            username = st.text_input(
                "Username",
                value="admin"
            )

            ip_address = st.text_input(
                "IP Address",
                value="198.51.100.25"
            )

            result_type = st.selectbox(
                "Login Result",
                ["FAILED", "SUCCESS"]
            )

            submitted = st.form_submit_button(
                "Generate Login Event",
                use_container_width=True
            )

        if submitted:

            try:

                if not username.strip():
                    raise ValueError("Username is required")

                result = simulate_login(
                    username=username.strip(),
                    ip_address=ip_address.strip(),
                    success=(result_type == "SUCCESS")
                )

                if result["status"] == "SUCCESS":
                    st.success("Successful login event recorded.")

                else:
                    st.warning("Failed login event recorded.")

                    if result["detection"]["detected"]:
                        st.error(
                            "BRUTE-FORCE ATTACK DETECTED!"
                        )

                    else:
                        st.info(
                            "Monitoring failed login attempts: "
                            f"{result['detection']['failed_attempts']}"
                        )

            except ValueError as error:
                st.error(str(error))

    with tab2:

        st.subheader("Simulate Brute-Force Attack")

        st.write(
            "Generate repeated failed login events from "
            "a single IP address."
        )

        with st.form("attack_form"):

            attack_username = st.text_input(
                "Target Username",
                value="admin"
            )

            attack_ip = st.text_input(
                "Source IP Address",
                value="203.0.113.100"
            )

            attempts = st.slider(
                "Number of Failed Attempts",
                min_value=1,
                max_value=20,
                value=5
            )

            attack_submitted = st.form_submit_button(
                "🚨 Launch Simulated Attack",
                use_container_width=True
            )

        if attack_submitted:

            try:

                if not attack_username.strip():
                    raise ValueError("Username is required")

                results = simulate_brute_force(
                    username=attack_username.strip(),
                    ip_address=attack_ip.strip(),
                    attempts=attempts
                )

                detected = any(
                    item["detection"]["detected"]
                    for item in results
                )

                st.write(
                    f"Generated {len(results)} failed login events."
                )

                if detected:
                    st.error(
                        "HIGH SEVERITY: BRUTE-FORCE ATTACK DETECTED!"
                    )
                else:
                    st.success(
                        "Events recorded. Detection threshold not reached."
                    )

                st.dataframe(
                    pd.DataFrame([
                        {
                            "Username": item["username"],
                            "IP Address": item["ip_address"],
                            "Status": item["status"],
                            "Detected": item["detection"]["detected"]
                        }
                        for item in results
                    ]),
                    use_container_width=True,
                    hide_index=True
                )

            except ValueError as error:
                st.error(str(error))


# ---------------------------------------
# INCIDENT MANAGEMENT
# ---------------------------------------

elif page == "Incident Management":

    show_header(
        "Security Incident Management",
        "Review detected threats and manage incident status."
    )

    if st.button("🔄 Refresh Incidents"):
        st.rerun()

    alerts = load_alerts()

    if not alerts.empty:

        a1, a2, a3 = st.columns(3)

        a1.metric("Total Incidents", len(alerts))

        a2.metric(
            "Open Incidents",
            len(alerts[alerts["status"] == "Open"])
        )

        a3.metric(
            "Resolved Incidents",
            len(alerts[alerts["status"] == "Resolved"])
        )

        st.divider()

        st.subheader("Detected Security Incidents")

        st.dataframe(
            alerts,
            use_container_width=True,
            hide_index=True
        )

        st.divider()

        st.subheader("Update Incident Status")

        alert_options = {
            f"Incident #{row['id']} - {row['alert_type']} - {row['ip_address']}":
            row["id"]
            for _, row in alerts.iterrows()
        }

        selected_label = st.selectbox(
            "Select Incident",
            list(alert_options.keys())
        )

        selected_id = alert_options[selected_label]

        current_status = alerts[
            alerts["id"] == selected_id
        ]["status"].iloc[0]

        new_status = st.selectbox(
            "New Status",
            ["Open", "Investigating", "Resolved"],
            index=[
                "Open",
                "Investigating",
                "Resolved"
            ].index(current_status)
        )

        if st.button("Update Incident"):

            update_alert_status(
                selected_id,
                new_status
            )

            st.success(
                f"Incident #{selected_id} updated to {new_status}."
            )

            st.rerun()

    else:
        st.success("No security incidents detected yet.")

    st.divider()

    st.caption(
        "ThreatLens | Security Operations Platform"
    )

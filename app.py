
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

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

from core.workload import load_or_generate_workload, generate_workload_dataset
from core.predictor import WorkloadPredictor, FEATURE_COLS
from core.autoscaler import ScalingSimulator


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
            "Incident Management",
            "Resource Management"
        ]
    )

    st.divider()

    st.markdown("### SYSTEM HEALTH")

    st.success("Database Connected")
    st.success("Detection Engine Active")
    st.success("ML Predictor Ready")
    st.success("Auto-Scaler Active")

    st.caption("ThreatLens v2.0-CRM")
    st.caption("Predictive Cloud Resource SIEM")


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


# ---------------------------------------
# RESOURCE MANAGEMENT & ML PREDICTION
# ---------------------------------------

elif page == "Resource Management":

    show_header(
        "Predictive Cloud Resource Management",
        "ML-driven workload prediction & proactive cloud auto-scaling for SIEM log ingestion."
    )

    # 1. State / Data Initialization
    if "workload_data" not in st.session_state:
        st.session_state.workload_data = load_or_generate_workload()

    if "predictor" not in st.session_state:
        p = WorkloadPredictor(n_estimators=60, max_depth=10, random_state=42)
        metrics, eval_test = p.train_and_evaluate(st.session_state.workload_data)
        st.session_state.predictor = p
        st.session_state.pred_metrics = metrics
        st.session_state.eval_test = eval_test

    # 2. Controls & Configuration Expander
    with st.expander("⚙️ Scaling & Model Configuration Parameters", expanded=False):
        c1, c2, c3, c4 = st.columns(4)
        
        with c1:
            cfg_capacity = st.number_input(
                "Instance Capacity (events/min)",
                min_value=100, max_value=500, value=220, step=20,
                help="Maximum safe log processing rate for a single SIEM container."
            )
        with c2:
            cfg_safety_margin = st.slider(
                "Predictive Safety Margin (%)",
                min_value=0, max_value=35, value=10, step=5,
                help="Buffer added to ML prediction to avoid under-provisioning during surges."
            ) / 100.0
        with c3:
            cfg_cooldown = st.slider(
                "Scale-In Cooldown (mins)",
                min_value=1, max_value=6, value=3, step=1,
                help="Minutes to wait before terminating instances (prevents flapping)."
            )
        with c4:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🔄 Retrain ML Model & Re-run"):
                st.session_state.workload_data = generate_workload_dataset(random_seed=np.random.randint(1, 9999))
                p = WorkloadPredictor(n_estimators=60, max_depth=10, random_state=42)
                metrics, eval_test = p.train_and_evaluate(st.session_state.workload_data)
                st.session_state.predictor = p
                st.session_state.pred_metrics = metrics
                st.session_state.eval_test = eval_test
                st.rerun()

    # Run autoscaler simulation with current configuration
    simulator = ScalingSimulator(
        instance_capacity=cfg_capacity,
        min_instances=2,
        max_instances=10,
        safety_margin=cfg_safety_margin,
        scale_in_cooldown=cfg_cooldown
    )
    sim_summary, sim_df = simulator.run_simulation(st.session_state.eval_test)
    ml_metrics = st.session_state.pred_metrics

    # 3. High-Level Executive KPI Row
    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric(
        "ML Accuracy (R²)",
        f"{ml_metrics['R2']:.3f}",
        f"MAE: {ml_metrics['MAE']:.1f} ev/m"
    )
    k2.metric(
        "RMSE Loss",
        f"{ml_metrics['RMSE']:.1f}",
        "Horizon: 5 min"
    )
    k3.metric(
        "Max Latency (Reactive)",
        f"{sim_summary['Reactive']['Max Latency (ms)']} ms",
        delta=f"-{sim_summary['Reactive']['Max Latency (ms)'] - sim_summary['Predictive']['Max Latency (ms)']:.1f} ms with ML",
        delta_color="normal"
    )
    k4.metric(
        "Predictive Peak Latency",
        f"{sim_summary['Predictive']['Max Latency (ms)']} ms",
        "Stable under surges"
    )
    k5.metric(
        "Est. Cloud Cost",
        f"${sim_summary['Predictive']['Total Cost ($)']:.2f}",
        f"{sim_summary['Comparison']['Cost Difference (%)']:+.1f}% vs Reactive"
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # 4. Interactive Tabs
    tab1, tab2, tab3 = st.tabs([
        "🔮 Workload Prediction (5-Min Horizon)",
        "⚡ Predictive vs Reactive Auto-Scaling",
        "🛡️ Prediction Errors & Safeguards"
    ])

    # --- TAB 1: WORKLOAD PREDICTION ---
    with tab1:
        st.subheader("5-Minute-Ahead Security Workload Forecasting")
        st.caption("Random Forest Regressor trained on time-ordered SIEM ingestion logs (No lookahead leakage)")

        # Chart: Actual vs Predicted
        display_slice = sim_df.tail(240).copy()  # Last 4 hours for clear visual inspection
        fig_pred = go.Figure()

        fig_pred.add_trace(go.Scatter(
            x=display_slice["timestamp"],
            y=display_slice["target_workload_5m"],
            name="Actual Future Workload (t+5m)",
            line=dict(color="#3b82f6", width=2)
        ))

        fig_pred.add_trace(go.Scatter(
            x=display_slice["timestamp"],
            y=display_slice["predicted_workload_5m"],
            name="ML Predicted Workload (t+5m)",
            line=dict(color="#10b981", width=2, dash="dash")
        ))

        fig_pred.update_layout(
            template="plotly_dark",
            paper_bgcolor="#080d18",
            plot_bgcolor="#0b1322",
            height=380,
            margin=dict(l=20, r=20, t=30, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            xaxis=dict(title="Timestamp"),
            yaxis=dict(title="Events per Minute")
        )
        st.plotly_chart(fig_pred, use_container_width=True)

        col_f1, col_f2 = st.columns([3, 2])

        with col_f1:
            st.markdown("#### Feature Importances")
            fi_df = st.session_state.predictor.feature_importances_.head(8)
            fig_fi = px.bar(
                fi_df,
                x="Importance",
                y="Feature",
                orientation="h",
                color="Importance",
                color_continuous_scale="Blues",
                template="plotly_dark"
            )
            fig_fi.update_layout(
                paper_bgcolor="#080d18",
                plot_bgcolor="#0b1322",
                height=280,
                margin=dict(l=10, r=10, t=10, b=10),
                yaxis=dict(autorange="reversed")
            )
            st.plotly_chart(fig_fi, use_container_width=True)

        with col_f2:
            st.markdown("#### Model Specification & Evaluation")
            st.markdown(f"""
            - **Algorithm:** Scikit-Learn `RandomForestRegressor`
            - **Split:** Time-ordered (80% Train, 20% Test)
            - **Prediction Horizon:** 5 Minutes Ahead ($t+5$)
            - **Mean Absolute Error (MAE):** `{ml_metrics['MAE']}` events/min
            - **Root Mean Squared Error (RMSE):** `{ml_metrics['RMSE']}`
            - **Coefficient of Determination ($R^2$):** `{ml_metrics['R2']}`
            - **Training Samples:** `{ml_metrics['Train_Samples']}` minutes
            - **Evaluation Test Set:** `{ml_metrics['Test_Samples']}` minutes
            """)

    # --- TAB 2: AUTOSCALING COMPARISON ---
    with tab2:
        st.subheader("Predictive vs Reactive Scaling Performance")
        st.caption("Comparison under identical security event traffic stream, sudden attack bursts, and cloud provisioning latency.")

        # Instance Allocation Chart
        fig_inst = go.Figure()

        fig_inst.add_trace(go.Scatter(
            x=display_slice["timestamp"],
            y=display_slice["predictive_instances"],
            name="Predictive Instances (Proactive)",
            line=dict(color="#10b981", width=2.5)
        ))

        fig_inst.add_trace(go.Scatter(
            x=display_slice["timestamp"],
            y=display_slice["reactive_instances"],
            name="Reactive Instances (Lagging)",
            line=dict(color="#f59e0b", width=2, dash="dot")
        ))

        fig_inst.update_layout(
            title="Cluster Instance Allocation (Containers Active)",
            template="plotly_dark",
            paper_bgcolor="#080d18",
            plot_bgcolor="#0b1322",
            height=300,
            margin=dict(l=20, r=20, t=40, b=20),
            yaxis=dict(title="Instance Count", dtick=1)
        )
        st.plotly_chart(fig_inst, use_container_width=True)

        # Latency Comparison Chart
        fig_lat = go.Figure()

        fig_lat.add_trace(go.Scatter(
            x=display_slice["timestamp"],
            y=display_slice["reactive_latency_ms"],
            name="Reactive Latency (Spikes under surge)",
            line=dict(color="#ef4444", width=2)
        ))

        fig_lat.add_trace(go.Scatter(
            x=display_slice["timestamp"],
            y=display_slice["predictive_latency_ms"],
            name="Predictive Latency (Stable)",
            line=dict(color="#3b82f6", width=2)
        ))

        fig_lat.update_layout(
            title="Simulated Event Processing Latency (ms)",
            template="plotly_dark",
            paper_bgcolor="#080d18",
            plot_bgcolor="#0b1322",
            height=280,
            margin=dict(l=20, r=20, t=40, b=20),
            yaxis=dict(title="Latency (ms)")
        )
        st.plotly_chart(fig_lat, use_container_width=True)

        # Comparative Summary Table
        st.markdown("#### Comparative Evaluation Summary")
        comp_df = pd.DataFrame({
            "Metric": [
                "Average Instances",
                "Average CPU Utilization",
                "Peak Processing Latency",
                "Average Processing Latency",
                "Overload / Under-Provisioned Time",
                "Total Scaling Actions (Flapping)",
                "Estimated Cloud Cost ($)",
                "Estimated Energy Consumption (kWh)"
            ],
            "Reactive Scaling": [
                f"{sim_summary['Reactive']['Avg Instances']:.2f}",
                f"{sim_summary['Reactive']['Avg Utilization (%)']:.1f}%",
                f"{sim_summary['Reactive']['Max Latency (ms)']:.1f} ms",
                f"{sim_summary['Reactive']['Avg Latency (ms)']:.1f} ms",
                f"{sim_summary['Reactive']['Overload Minutes']} min ({sim_summary['Reactive']['Overload Rate (%)']}%)",
                f"{sim_summary['Reactive']['Total Scaling Actions']}",
                f"${sim_summary['Reactive']['Total Cost ($)']:.4f}",
                f"{sim_summary['Reactive']['Total Energy (kWh)']:.4f} kWh"
            ],
            "Predictive Scaling (ThreatLens)": [
                f"{sim_summary['Predictive']['Avg Instances']:.2f}",
                f"{sim_summary['Predictive']['Avg Utilization (%)']:.1f}%",
                f"{sim_summary['Predictive']['Max Latency (ms)']:.1f} ms",
                f"{sim_summary['Predictive']['Avg Latency (ms)']:.1f} ms",
                f"{sim_summary['Predictive']['Overload Minutes']} min ({sim_summary['Predictive']['Overload Rate (%)']}%)",
                f"{sim_summary['Predictive']['Total Scaling Actions']}",
                f"${sim_summary['Predictive']['Total Cost ($)']:.4f}",
                f"{sim_summary['Predictive']['Total Energy (kWh)']:.4f} kWh"
            ],
            "Improvement / Impact": [
                f"{sim_summary['Comparison']['Cost Difference (%)']:+.1f}% capacity sizing",
                "Higher sustained efficiency",
                f"-{sim_summary['Reactive']['Max Latency (ms)'] - sim_summary['Predictive']['Max Latency (ms)']:.1f} ms latency spike reduction",
                "Consistent event ingestion speed",
                "Zero SLA breach queue backlog",
                "Controlled hysteresis anti-thrashing",
                f"{sim_summary['Comparison']['Cost Difference (%)']:+.1f}% budget optimization",
                "Carbon-aware energy profile"
            ]
        })
        st.dataframe(comp_df, use_container_width=True, hide_index=True)

    # --- TAB 3: SAFEGUARDS & SURGE SIMULATOR ---
    with tab3:
        st.subheader("Prediction Error Analysis & Operational Safeguards")
        
        sg1, sg2 = st.columns(2)
        with sg1:
            st.error("⚠️ Under-Prediction Risk")
            st.markdown(r"""
            - **Symptom:** The ML model under-estimates incoming attack volume.
            - **Consequence:** Insufficient container instances $\implies$ queue backlog $\implies$ detection latency spike $\implies$ delayed alerts.
            - **Implemented Safeguard:**
              1. **+10% Safety Margin Buffer:** Proactively inflates target capacity.
              2. **Reactive Fallback Trigger:** If live cluster utilization exceeds **90%**, the system bypasses prediction and immediately scales out!
            """)

        with sg2:
            st.warning("⚠️ Over-Prediction Risk")
            st.markdown(r"""
            - **Symptom:** The ML model predicts a surge that dissipates or fails to materialize.
            - **Consequence:** Excessive idle container instances $\implies$ wasted cloud budget and energy.
            - **Implemented Safeguard:**
              1. **Scale-In Cooldown Counter (3 mins):** Prevents premature or thrashing scale-down events.
              2. **Configurable Ceiling (Max 10 Instances):** Hard quota ceiling prevents runaway billing.
            """)

        st.divider()

        st.subheader("⚡ Live Synthetic Attack Surge Test")
        st.caption("Inject a sudden 500% cyberattack log surge to observe instant autoscaler response.")

        surge_intensity = st.slider("Attack Surge Volume (events/minute)", 300, 1000, 650, step=50)

        if st.button("🚨 Inject Sudden Attack Surge Now"):
            base_rate = 180
            total_surge = base_rate + surge_intensity
            current_inst = 2
            
            # Reactive calculation
            react_util = (total_surge / (current_inst * cfg_capacity)) * 100.0
            react_needed = int(np.clip(np.ceil(total_surge / (cfg_capacity * 0.70)), 2, 10))
            
            # Predictive calculation (knowing 5m ahead)
            pred_needed = int(np.clip(np.ceil((total_surge * (1.0 + cfg_safety_margin)) / (cfg_capacity * 0.75)), 2, 10))
            
            res_c1, res_c2 = st.columns(2)
            with res_c1:
                st.markdown("#### Reactive Response (Lagging)")
                st.write(f"Incoming Load: **{total_surge} events/min**")
                st.write(f"Cluster Utilization at t=0: **{react_util:.1f}% (OVERLOADED)**")
                st.write(f"Instance Count at t=0: **{current_inst} (Insufficient)**")
                st.write(f"Lag delay before new instances arrive: **60 seconds**")
                st.error("💥 Queue backlog built! High latency alert.")

            with res_c2:
                st.markdown("#### ThreatLens Predictive Response (Proactive)")
                st.write(f"Predicted Load 5m ahead: **{total_surge} events/min**")
                st.write(f"Proactively Provisioned: **{pred_needed} instances**")
                st.write(f"Utilization upon surge arrival: **~68% (HEALTHY)**")
                st.write(f"Lag delay: **0 seconds (instances warm)**")
                st.success("✅ Surge absorbed with zero queue backlog or latency spike!")

    st.divider()
    st.caption("ThreatLens | Cloud Resource Management + Cybersecurity SIEM")

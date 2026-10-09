# frontend/streamlit_app.py
"""
Streamlit dashboard for the AI SOC Copilot.
Talks to the FastAPI backend running on http://127.0.0.1:8000
"""
import streamlit as st
import requests
import pandas as pd

API_URL = "http://127.0.0.1:8000"

st.set_page_config(page_title="AI SOC Copilot", page_icon="🛡️", layout="wide")

st.title("🛡️ AI SOC Copilot")
st.markdown("Parse Linux logs, detect threats, and triage alerts.")

# ----------------------------- Sidebar --------------------------------- #

st.sidebar.header("Actions")

if st.sidebar.button("📥 Load Demo Data (auth.log)"):
    with st.spinner("Ingesting..."):
        try:
            resp = requests.post(
                f"{API_URL}/ingest-path",
                json={"path": "data/auth.log", "source": "auth"},
            )
            if resp.status_code == 200:
                data = resp.json()
                st.sidebar.success(f"Loaded {data['events_parsed']} events!")
            else:
                st.sidebar.error(f"Error: {resp.text}")
        except Exception as e:
            st.sidebar.error(f"API connection failed: {e}")

if st.sidebar.button("🗑️ Reset Data"):
    try:
        requests.post(f"{API_URL}/reset")
        st.sidebar.success("Data cleared.")
    except Exception as e:
        st.sidebar.error(f"API connection failed: {e}")

# ----------------------------- Health Metrics --------------------------- #

try:
    health = requests.get(f"{API_URL}/health", timeout=2).json()
except Exception:
    health = {"events": 0, "alerts": 0}
    st.warning("⚠️ Cannot reach API. Is `uvicorn` running on port 8000?")

col1, col2 = st.columns(2)
col1.metric("Total Events", health["events"])
col2.metric("Total Alerts", health["alerts"])

st.divider()

# ----------------------------- Fetch Data ------------------------------- #
# We fetch the alerts data BEFORE the tabs so the AI Triage section at the bottom can use it.

try:
    alerts_response = requests.get(f"{API_URL}/alerts").json()
    alerts_data = pd.DataFrame(alerts_response.get("alerts", []))
except Exception:
    alerts_data = pd.DataFrame()

# ----------------------------- Tabs ------------------------------------- #

tab1, tab2 = st.tabs(["🚨 Alerts", "📜 Raw Events"])

with tab1:
    st.subheader("Detected Alerts")
    if not alerts_data.empty:
        df = alerts_data.copy()
        severity = st.selectbox(
            "Filter by severity",
            ["All"] + sorted(df["severity"].unique().tolist()),
        )
        if severity != "All":
            df = df[df["severity"] == severity]

        st.dataframe(
            df[["ts", "rule_id", "rule_name", "severity", "summary", "user", "ip"]],
            width='stretch',
        )
    else:
        st.info("No alerts yet. Click 'Load Demo Data' in the sidebar.")

with tab2:
    st.subheader("Parsed Events")
    try:
        events_data = requests.get(f"{API_URL}/events").json()["events"]
    except Exception:
        events_data = []

    if events_data:
        df_ev = pd.DataFrame(events_data)
        etype = st.selectbox(
            "Filter by event type",
            ["All"] + sorted(df_ev["event_type"].unique().tolist()),
        )
        if etype != "All":
            df_ev = df_ev[df_ev["event_type"] == etype]

        st.dataframe(
            df_ev[["ts", "event_type", "user", "ip", "raw"]],
            width='stretch',
        )
    else:
        st.info("No events yet. Click 'Load Demo Data' in the sidebar.")

# ----------------------------- AI Copilot Triage ------------------------ #

st.markdown("---")
st.subheader("🤖 AI Copilot Triage")

if not alerts_data.empty:
    # Create a dropdown to select an alert by its index or summary
    alert_options = [f"{row['rule_name']} - {row['summary']}" for index, row in alerts_data.iterrows()]
    selected_alert_str = st.selectbox("Select an Alert to Analyze", alert_options)

    if st.button("🧠 Analyze with AI"):
        if selected_alert_str:
            # Find the selected alert data
            selected_index = alert_options.index(selected_alert_str)
            alert_data = alerts_data.iloc[selected_index].to_dict()
            
            with st.spinner("AI is analyzing the alert..."):
                # Send to FastAPI backend
                payload = {
                    "rule_name": str(alert_data.get("rule_name", "")),
                    "severity": str(alert_data.get("severity", "")),
                    "summary": str(alert_data.get("summary", "")),
                    "raw_log": str(alert_data.get("raw_log", "Raw log not captured")) 
                }
                
                try:
                    response = requests.post(f"{API_URL}/triage", json=payload)
                    if response.status_code == 200:
                        st.success("Analysis Complete!")
                        st.markdown(response.json()["analysis"])
                    else:
                        st.error(f"Error from backend: {response.text}")
                except Exception as e:
                    st.error(f"Failed to connect to backend: {e}")
else:
    st.info("No alerts to triage. Please load data first.")

from pathlib import Path

import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent
REPORT_FILE = BASE_DIR / "security_alerts.csv"

st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Security Operations Dashboard")
st.caption("Python Security Log Analyzer | SOC Portfolio Project")

if not REPORT_FILE.exists():
    st.error("No security report found. Run analyzer.py first.")
    st.stop()

try:
    df = pd.read_csv(REPORT_FILE)
except (OSError, pd.errors.ParserError) as error:
    st.error(f"Unable to read security report: {error}")
    st.stop()

if df.empty:
    st.success("No security alerts detected.")
    st.stop()

required_columns = {
    "ip_address", "username", "severity",
    "detection", "failed_attempts", "timestamp"
}

if not required_columns.issubset(df.columns):
    st.error("The security report is missing required columns.")
    st.stop()

df["timestamp"] = pd.to_datetime(
    df["timestamp"], errors="coerce"
)

df = df.sort_values("timestamp", ascending=False)

# Dashboard summary
total = len(df)
high = (df["severity"] == "HIGH").sum()
critical = (df["severity"] == "CRITICAL").sum()
unique_ips = df["ip_address"].nunique()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", total)
col2.metric("High Alerts", high)
col3.metric("Critical Alerts", critical)
col4.metric("Unique Source IPs", unique_ips)

st.divider()

# Search and filtering
st.subheader("Investigate Security Alerts")

search = st.text_input(
    "Search IP Address or Username",
    placeholder="Enter an IP address or username"
)

severity_options = sorted(df["severity"].dropna().unique())

selected_severity = st.multiselect(
    "Filter by Severity",
    options=severity_options,
    default=severity_options
)

filtered_df = df[
    df["severity"].isin(selected_severity)
].copy()

if search:
    search_mask = (
        filtered_df["ip_address"].astype(str).str.contains(
            search, case=False, regex=False
        )
        |
        filtered_df["username"].astype(str).str.contains(
            search, case=False, regex=False
        )
    )
    filtered_df = filtered_df[search_mask]

st.write(f"Showing {len(filtered_df)} matching alert(s)")

st.dataframe(
    filtered_df,
    use_container_width=True,
    hide_index=True
)

st.divider()

# Timeline visualization
st.subheader("Security Alert Timeline")

if not filtered_df.empty:
    timeline = (
        filtered_df.dropna(subset=["timestamp"])
        .groupby([
            pd.Grouper(key="timestamp", freq="min"),
            "severity"
        ])
        .size()
        .unstack(fill_value=0)
    )

    if not timeline.empty:
        st.line_chart(timeline)
    else:
        st.info("No valid timestamps available for the timeline.")
else:
    st.info("No alerts match your current filters.")

# Export investigation results
st.subheader("Export Investigation Results")

st.download_button(
    label="Download Filtered Security Report",
    data=filtered_df.to_csv(index=False),
    file_name="investigation_report.csv",
    mime="text/csv"
)

st.divider()
st.caption("Local Cybersecurity Lab | Simulated Security Events")

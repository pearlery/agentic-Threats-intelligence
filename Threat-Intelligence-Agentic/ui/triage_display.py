import streamlit as st
import json
import os

def display_alert_history():
    st.header("📋 Alert Triage History")

    file_path = "data/alert_history.jsonl"

    if not os.path.exists(file_path):
        st.info("No alerts have been received yet.")
        return

    # ปุ่ม refresh
    if st.button("🔄 Refresh Alerts"):
        st.experimental_rerun()

    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if not lines:
        st.warning("No alert entries found.")
        return

    for line in reversed(lines[-50:]):  # โชว์ 50 รายการล่าสุด
        try:
            data = json.loads(line)
            alert = data.get("alert", {})
            triage = data.get("triage", "❔ Unknown")

            st.markdown("---")
            st.markdown(f"**🆔 Alert ID:** `{alert.get('id', 'N/A')}`")
            st.markdown(f"**📛 Type:** `{alert.get('type', 'N/A')}`")
            st.markdown(f"**🔥 Severity:** `{alert.get('severity', 'N/A')}`")
            st.markdown(f"**🏷 Tags:** {', '.join(alert.get('tags', []))}")
            st.markdown(f"**🧪 Triage Result:** {triage}")

        except json.JSONDecodeError:
            st.error("⚠️ Failed to parse alert entry.")

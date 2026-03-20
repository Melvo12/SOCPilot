import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st
from app.analyzer import analyze_log
from datetime import datetime

st.set_page_config(
    page_title="SOCPilot",
    page_icon="🛡️",
    layout="centered"
)

st.markdown("""
<style>
  .block-container { padding-top: 2rem; max-width: 780px; }
  .soc-header { text-align: center; margin-bottom: 2rem; }
  .soc-header h1 { font-size: 2rem; font-weight: 800; color: var(--text-color); margin-bottom: 0.2rem; }
  .soc-header p  { color: #6e7891; font-size: 0.95rem; }
  .severity-badge {
    display: inline-block; padding: 6px 18px; border-radius: 20px;
    font-weight: 700; font-size: 0.85rem; letter-spacing: 0.1em; margin-bottom: 1rem;
  }
  .sev-critical { background:#ff000022; color:#ff4d4d; border:1px solid #ff4d4d55; }
  .sev-high     { background:#ff450022; color:#ff6b35; border:1px solid #ff6b3555; }
  .sev-medium   { background:#ffa04022; color:#ffa040; border:1px solid #ffa04055; }
  .sev-low      { background:#00d4a022; color:#00d4a0; border:1px solid #00d4a055; }
  .sev-unknown  { background:#6e789122; color:#6e7891; border:1px solid #6e789155; }
  .result-box {
    background: #0d1117; border: 1px solid #1e2a3a;
    border-radius: 12px; padding: 1.5rem; margin-top: 1rem;
  }
  .result-label {
    font-size: 0.75rem; font-weight: 600; letter-spacing: 0.1em;
    color: #6e7891; text-transform: uppercase; margin-bottom: 0.4rem;
  }
  .result-value { color: #e8eaf0; font-size: 0.95rem; line-height: 1.6; }
  .action-item {
    background: #161b25; border: 1px solid #1e2a3a; border-radius: 8px;
    padding: 8px 14px; margin-bottom: 6px; color: #c9d0e3; font-size: 0.9rem;
  }
  .mitre-tag {
    display: inline-block; background: #4d9eff18; color: #4d9eff;
    border: 1px solid #4d9eff33; border-radius: 6px;
    padding: 4px 12px; font-size: 0.8rem; font-family: monospace;
  }
  .divider { border: none; border-top: 1px solid #1e2a3a; margin: 1rem 0; }
  .format-hint {
    background: #0d1117; border: 1px solid #1e2a3a; border-radius: 8px;
    padding: 10px 14px; font-family: monospace; font-size: 0.8rem;
    color: #6e7891; line-height: 1.8; margin-bottom: 12px;
  }
  .report-box {
    background: #0d1117; border: 1px solid #1e2a3a; border-radius: 12px;
    padding: 1.5rem; font-family: monospace; font-size: 0.85rem;
    color: #c9d0e3; line-height: 1.8; white-space: pre-wrap; margin-top: 1rem;
  }
</style>
""", unsafe_allow_html=True)

# Formato de referencia
LOG_FORMAT = """Event Type: [e.g. Failed Login / Port Scan / Data Transfer / Malware Alert]
Source IP: 
Destination IP / Target: 
Protocol: 
Port: 
Timestamp: 
Duration: 
Additional Details: """

st.markdown("""
<div class="soc-header">
  <h1>🛡️ SOCPilot</h1>
  <p>On-Prem AI Assistant · Incident Analysis in Seconds</p>
</div>
""", unsafe_allow_html=True)

tab1, tab2 = st.tabs(["Analyze Event", "Incident Report"])

# ════════════════════════════════════════════════════════════════════
# TAB 1 — Analyze Event
# ════════════════════════════════════════════════════════════════════
with tab1:

    st.caption("Use the format below for best results — click the copy icon in the top right corner.")
    st.code(LOG_FORMAT, language=None)

    log_input = st.text_area(
        "Security event",
        height=200,
        placeholder="Event Type: Failed Login\nSource IP: 45.83.122.14\nDestination IP / Target: corp\\admin.jsmith\nProtocol: SSH\nPort: 22\nTimestamp: 2024-01-15 03:42:11\nAdditional Details: 312 failed attempts in 4 minutes",
        label_visibility="collapsed"
    )

    analyze_btn = st.button("Analyze", use_container_width=True, type="primary")

    if analyze_btn:
        if not log_input.strip():
            st.warning("Paste a security event first.")
        else:
            with st.spinner("Analyzing event..."):
                result = analyze_log(log_input)
                st.session_state["last_result"] = result
                st.session_state["last_log"]    = log_input

            severity  = result.get("severity", "UNKNOWN").upper()
            sev_class = {
                "CRITICAL": "sev-critical",
                "HIGH":     "sev-high",
                "MEDIUM":   "sev-medium",
                "LOW":      "sev-low",
            }.get(severity, "sev-unknown")

            st.markdown(f"""
            <div class="result-box">
              <span class="severity-badge {sev_class}">{severity}</span>
              <div class="result-label">Category</div>
              <div class="result-value" style="margin-bottom:1rem">
                {result.get("category", "N/A")}
              </div>
              <hr class="divider"/>
              <div class="result-label">Observation</div>
              <div class="result-value" style="margin-bottom:1rem">
                {result.get("observation", "N/A")}
              </div>
              <hr class="divider"/>
              <div class="result-label">Recommended Actions</div>
            </div>
            """, unsafe_allow_html=True)

            for action in result.get("actions", []):
                st.markdown(f'<div class="action-item">— {action}</div>', unsafe_allow_html=True)

            mitre = result.get("mitre_technique", "")
            if mitre and mitre != "N/A":
                st.markdown(f'<br><span class="mitre-tag">MITRE: {mitre}</span>', unsafe_allow_html=True)

            st.info("Go to the **Incident Report** tab to generate the full formatted report.")

# ════════════════════════════════════════════════════════════════════
# TAB 2 — Incident Report
# ════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("##### Incident Report")
    st.caption("AI-generated fields are pre-filled from your last analysis. Fill in the manual fields and generate the report.")

    result = st.session_state.get("last_result", {})

    col1, col2 = st.columns(2)
    with col1:
        incident_id    = st.text_input("Incident ID", placeholder="INC-2024-001")
        analyst        = st.text_input("Analyst Name", placeholder="John Smith")
    with col2:
        date_time      = st.text_input("Date / Time", value=datetime.now().strftime("%Y-%m-%d %H:%M"))
        affected_asset = st.text_input("Affected Asset", placeholder="corp\\admin.jsmith / 192.168.1.50")

    severity = st.selectbox(
        "Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        index=["CRITICAL","HIGH","MEDIUM","LOW"].index(
            result.get("severity", "HIGH")
            if result.get("severity", "HIGH") in ["CRITICAL","HIGH","MEDIUM","LOW"]
            else "HIGH"
        )
    )

    category    = st.text_input("Category",    value=result.get("category", ""))
    observation = st.text_area("Observation",  value=result.get("observation", ""), height=100)

    actions_default = "\n".join(f"- {a}" for a in result.get("actions", []))
    actions = st.text_area("Recommended Actions", value=actions_default, height=100)

    mitre = st.text_input("MITRE Technique", value=result.get("mitre_technique", ""))
    notes = st.text_area("Additional Notes", placeholder="Extra context, evidence, follow-up items...", height=80)

    if st.button("Generate Report", use_container_width=True, type="primary"):
        report = f"""
================================================================================
                         INCIDENT REPORT — SOCPilot
================================================================================
Incident ID   : {incident_id or 'N/A'}
Date / Time   : {date_time}
Analyst       : {analyst or 'N/A'}
Affected Asset: {affected_asset or 'N/A'}
Severity      : {severity}
Category      : {category}
--------------------------------------------------------------------------------
OBSERVATION
{observation}
--------------------------------------------------------------------------------
RECOMMENDED ACTIONS
{actions}
--------------------------------------------------------------------------------
MITRE ATT&CK  : {mitre or 'N/A'}
--------------------------------------------------------------------------------
ADDITIONAL NOTES
{notes or 'None'}
================================================================================
Generated by SOCPilot — On-Prem AI Assistant
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
================================================================================
""".strip()

        st.markdown('<div class="report-box">' + report + '</div>', unsafe_allow_html=True)

        st.download_button(
            label="Download Report (.txt)",
            data=report,
            file_name=f"incident_report_{incident_id or 'draft'}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
            mime="text/plain",
            use_container_width=True
        )


        
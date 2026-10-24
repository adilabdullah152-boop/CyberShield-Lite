
import streamlit as st
import platform
import psutil
import pandas as pd
from datetime import datetime

def get_listening_ports():
    
    listening_ports = []

    for connection in psutil.net_connections(kind="inet"):
        if connection.status == psutil.CONN_LISTEN:
            if connection.laddr:
                listening_ports.append({
                    "IP Address": connection.laddr.ip,
                    "Port": connection.laddr.port
                })

    return listening_ports

def assess_port_risk(port):
    review_ports = {
        21: "FTP - review whether encrypted transfer is used",
        23: "Telnet - review because it does not encrypt traffic",
        445: "SMB - review file-sharing exposure",
        3389: "Remote Desktop - review remote-access settings"
    }

    if port in review_ports:
        return "Review", review_ports[port]

    return "No rule matched", "This simple check found no specific rule for this port"

st.set_page_config(
    page_title="CyberShield Lite",
    page_icon="🛡️",
    layout="wide"
)

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []


st.title("🛡️ CyberShield Lite")
st.info(
    "🛡️ Welcome to CyberShield Lite! "
    "Monitor your system, review listening ports, "
    "and follow your personal security checklist."
)

st.write("Your personal cybersecurity dashboard")
st.sidebar.title("🛡️ CyberShield Lite")

st.sidebar.write("Personal Security Dashboard")

st.sidebar.markdown("---")

st.sidebar.info(
    "Use this tool to review system usage "
    "and listening network ports."
)
st.divider()

operating_system = platform.system()
architecture = platform.machine()

if st.button("🔄 Refresh System Status"):
    st.rerun()

memory = psutil.virtual_memory()
total_ram = memory.total / (1024 ** 3)
available_ram = memory.available / (1024 ** 3)
ram_used = memory.percent
cpu_used = psutil.cpu_percent(interval=1)
if cpu_used < 50:
    st.success("CPU usage is low.")
elif cpu_used < 80:
    st.warning("CPU usage is moderate.")
else:
    st.error("CPU usage is high.")


col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("💻 Operating System")
    st.metric("System", operating_system)

with col2:
    st.subheader("🧠 RAM Usage")
    st.metric("Memory Used", f"{ram_used}%")
    st.progress(ram_used / 100)

with col3:
    st.subheader("⚙️ CPU Usage")
    st.metric("Processor Used", f"{cpu_used}%")
    st.progress(cpu_used / 100)

st.divider()

st.subheader("📊 Detailed Memory Information")

col4, col5 = st.columns(2)

with col4:
    st.metric("Total RAM", f"{total_ram:.2f} GB")

with col5:
    st.metric("Available RAM", f"{available_ram:.2f} GB")

st.info(
    "These are system usage measurements, "
    "not a complete cybersecurity scan."
)

st.divider()

st.subheader("🌐 Local Network Port Check")

st.write(
    "Check which network ports are listening "
    "on your own computer."
)


if st.button("Check Listening Ports"):
    try:
        ports = get_listening_ports()
        scan_record = {
    "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "Ports Found": len(ports),
    "Ports Flagged": sum(
        1 for item in ports
        if assess_port_risk(item["Port"])[0] == "Review"
    )
}

        st.session_state.scan_history.append(scan_record)

        if ports:
            for item in ports:
                risk, explanation = assess_port_risk(item["Port"])
                item["Assessment"] = risk
                item["Explanation"] = explanation
                report_df = pd.DataFrame(ports)

            report_csv = report_df.to_csv(index=False).encode("utf-8")

            st.download_button(
                label="📥 Download Port Report",
                data=report_csv,
                file_name="cybershield_port_report.csv",
                mime="text/csv"
            )

            st.dataframe(ports, use_container_width=True)
            st.write(f"Listening ports found: {len(ports)}")

            review_count = sum(
                1 for item in ports
                if item["Assessment"] == "Review"
            )
            
            risk_score = min(review_count * 25, 100)

            if risk_score == 0:
                risk_label = "No port rules matched"
            elif risk_score <= 25:
                risk_label = "A few items need review"
            elif risk_score <= 50:
                risk_label = "Several items need review"
            else:
                risk_label = "Multiple items need review"

            st.subheader("🔎 Preliminary Risk Summary")
            st.metric("Rule-based indicator", f"{risk_score}/100")
            st.write("Summary:", risk_label)


            st.metric("Ports flagged for review", review_count)

            st.caption(
                "These are preliminary indicators, not proof of a vulnerability."
            )
        else:
            st.info("No listening ports were found or visible.")

    except psutil.AccessDenied:
        st.warning(
            "Access was denied. Some network information "
            "may require additional permissions."
        )
    except OSError as error:
        st.error(f"Could not read network information: {error}")


st.divider()

st.subheader("✅ Personal Security Checklist")
st.write("Review these security settings on your computer.")

firewall_checked = st.checkbox(
    "I have checked that my firewall is enabled."
)

updates_checked = st.checkbox(
    "I have checked for operating system updates."
)

antivirus_checked = st.checkbox(
    "I have checked that antivirus protection is active."
)

password_checked = st.checkbox(
    "I use strong, unique passwords for my accounts."
)

checked_count = sum([
    firewall_checked,
    updates_checked,
    antivirus_checked,
    password_checked
])

st.progress(checked_count / 4)

st.write(f"Checklist completed: {checked_count} out of 4")

if checked_count == 4:
    st.success("You have completed the checklist!")
else:
    st.info("Review the remaining items when you have time.")
st.divider()

st.subheader("🕘 Scan History")
if st.button("🗑️ Clear Scan History"):
    st.session_state.scan_history = []
    st.rerun()

if st.session_state.scan_history:
    history_df = pd.DataFrame(st.session_state.scan_history)

    st.dataframe(
        history_df,
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No scans recorded in this session yet.")
    st.divider()

st.subheader("💡 Security Recommendations")

st.markdown("""
- Keep your operating system updated.
- Use strong, unique passwords for your accounts.
- Enable your computer's firewall.
- Disable network services you do not need.
- Review remote-access settings regularly.
- Avoid opening unknown links and attachments.
""")
st.divider()

st.subheader("ℹ️ About CyberShield Lite")

st.write("""
CyberShield Lite is a beginner-friendly personal
cybersecurity monitoring dashboard built with Python
and Streamlit.

It helps users:
- Monitor CPU and RAM usage.
- Review listening network ports.
- Export port scan reports.
- Track scans during the current session.
- Follow basic cybersecurity recommendations.

Note: This tool performs basic checks only. It does not
detect all malware, test every vulnerability, or guarantee
that a computer is secure.
""")
st.divider()

st.caption(
    "🛡️ CyberShield Lite | Built with Python and Streamlit | "
    "Educational project — basic checks only"
)
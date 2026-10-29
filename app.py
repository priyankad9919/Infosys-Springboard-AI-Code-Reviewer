import os
import streamlit as st
from src.validator import detect_and_validate
from src.rag_engine import query_knowledge_base
from src.workflow import run_analysis_pipeline
from src.report_generator import generate_pdf_report
from src.sarif_exporter import generate_sarif_report

def calculate_security_grade(findings):
    """Computes a repository health grade (A-F) based on finding severities."""
    if not findings:
        return "A+", "🟢 Passed (Production Ready)"
    
    high_count = sum(1 for f in findings if f.severity == "High")
    med_count = sum(1 for f in findings if f.severity == "Medium")
    
    # Grading logic
    score = (high_count * 15) + (med_count * 5)
    
    if score == 0:
        return "A", "🟢 Passed (Low Risk)"
    elif score <= 15:
        return "B", "🟡 Warning (Minor Fixes Needed)"
    elif score <= 30:
        return "C", "🟠 At Risk (Review Recommended)"
    elif score <= 50:
        return "D", "🔴 Failing (Critical Vulnerabilities)"
    else:
        return "F", "⛔ Critical Security Failure"

# --- Streamlit Page Configuration ---
st.set_page_config(
    page_title="AI Code Review & Security Analysis Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Modern Custom CSS Styling ---
st.markdown("""
    <style>
    /* Global Theme Adjustments */
    .main {
        background-color: #0e1117;
        color: #f3f4f6;
    }
    /* Metric Card Styling */
    .metric-card {
        background: #1f2937;
        border: 1px solid #374151;
        padding: 15px 20px;
        border-radius: 10px;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .metric-title {
        font-size: 14px;
        color: #9ca3af;
        font-weight: 600;
        text-transform: uppercase;
    }
    .metric-value {
        font-size: 24px;
        font-weight: bold;
        color: #ffffff;
        margin-top: 5px;
    }
    /* Expander Card Adjustments */
    .streamlit-expanderHeader {
        background-color: #161b22 !important;
        border-radius: 6px;
        border: 1px solid #30363d;
    }
    </style>
""", unsafe_allow_html=True)

# --- Header Section ---
st.title("🛡️ AI Code Review & Security Analysis Agent")
st.caption("Enterprise-Grade Multi-Agent SAST Pipeline | AST Parsing & RAG-Powered Knowledge Grounding")
st.markdown("---")

# --- Tabs Navigation ---
tab1, tab2 = st.tabs(["🚀 Code Inspection & SAST", "📚 Secure Coding Knowledge Base"])

with tab1:
    col_left, col_right = st.columns([1, 1], gap="medium")
    
    with col_left:
        st.subheader("📥 Code Submission Module")
        input_method = st.radio("Choose Input Method:", ["Paste Source Code", "Upload Source File (.py / .java)"], horizontal=True)
        
        code_content = ""
        if "Paste" in input_method:
            code_content = st.text_area("Paste Python or Java code below:", height=380, placeholder="// Paste source code here...", key="code_input_area")
        else:
            uploaded_file = st.file_uploader("Upload Python or Java file", type=["py", "java"], key="file_upload_widget")
            if uploaded_file:
                code_content = uploaded_file.read().decode("utf-8")
                st.code(code_content, language="java" if uploaded_file.name.endswith("java") else "python")

        analyze_clicked = st.button("🔍 Run SAST + Parallel Multi-Agent Analysis", type="primary", use_container_width=True)

        # When clicked, compute and SAVE results to st.session_state
        if analyze_clicked:
            if not code_content.strip():
                st.warning("⚠️ Please provide source code before running the analysis.")
            else:
                val_result = detect_and_validate(code_content)
                st.session_state.val_result = val_result
                
                if val_result.is_valid:
                    with st.spinner("🤖 Running Security Vulnerability Agent and Code Analysis Agent in parallel..."):
                        st.session_state.findings = run_analysis_pipeline(code_content, val_result.language)
                else:
                    st.session_state.findings = []

    with col_right:
        st.subheader("📊 Analysis Results & Metrics")
        
        # Render from session state so data persists across clicks
        if "val_result" in st.session_state:
            val_result = st.session_state.val_result
            
            if not val_result.is_valid:
                st.error(f"❌ Syntax Error Detected ({val_result.language.capitalize()}): {val_result.error_message}")
                if val_result.line_number:
                    st.warning(f"Error located around line: {val_result.line_number}")
            else:
                st.success(f"✅ Syntax Validation Passed — Detected Language: **{val_result.language.capitalize()}**")
                
                if "findings" in st.session_state:
                    if "findings" in st.session_state:
                        findings = st.session_state.findings
                    
                    # --- NEW: Calculate Quality Grade & Status ---
                    grade, gate_status = calculate_security_grade(findings)
                    
                    # --- Metrics & Quality Gate Header ---
                    high_cnt = sum(1 for f in findings if f.severity == "High")
                    med_cnt = sum(1 for f in findings if f.severity == "Medium")
                    low_cnt = sum(1 for f in findings if f.severity == "Low")
                    
                    # Display Quality Gate Status Banner
                    if grade in ["A+", "A", "B"]:
                        st.success(f"🛡️ **Quality Gate Status: {gate_status}** (Security Grade: **{grade}**)")
                    else:
                        st.error(f"🚨 **Quality Gate Status: {gate_status}** (Security Grade: **{grade}**)")
                    
                    # Metric Summary Cards
                    m1, m2, m3, m4, m5 = st.columns(5)
                    m1.markdown(f'<div class="metric-card"><div class="metric-title">Grade</div><div class="metric-value" style="color:#60a5fa;">{grade}</div></div>', unsafe_allow_html=True)
                    m2.markdown(f'<div class="metric-card"><div class="metric-title">Total</div><div class="metric-value">{len(findings)}</div></div>', unsafe_allow_html=True)
                    m3.markdown(f'<div class="metric-card"><div class="metric-title">High</div><div class="metric-value" style="color:#ef4444;">{high_cnt}</div></div>', unsafe_allow_html=True)
                    m4.markdown(f'<div class="metric-card"><div class="metric-title">Medium</div><div class="metric-value" style="color:#f59e0b;">{med_cnt}</div></div>', unsafe_allow_html=True)
                    m5.markdown(f'<div class="metric-card"><div class="metric-title">Low</div><div class="metric-value" style="color:#3b82f6;">{low_cnt}</div></div>', unsafe_allow_html=True)
                    
                    st.markdown("<br>", unsafe_allow_html=True)

                    if findings:
                        # Export buttons side-by-side
                        from src.sarif_exporter import generate_sarif_report
                        col_btn1, col_btn2 = st.columns(2)
                        
                        with col_btn1:
                            pdf_path = generate_pdf_report(findings)
                            with open(pdf_path, "rb") as pdf_file:
                                st.download_button("📥 Download Executive PDF Report", data=pdf_file, file_name="code_review_report.pdf", mime="application/pdf", use_container_width=True)
                                
                        with col_btn2:
                            sarif_json_str = generate_sarif_report(findings)
                            st.download_button("⚙️ Export SARIF Compliance JSON", data=sarif_json_str, file_name="security_compliance_report.sarif", mime="application/json", use_container_width=True)
                        
                        st.markdown("---")
                        
                        # --- NEW: Interactive Filter Toolbar ---
                        f_col1, f_col2 = st.columns(2)
                        with f_col1:
                            severity_filter = st.multiselect("Filter by Severity:", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
                        with f_col2:
                            agent_filter = st.multiselect("Filter by Agent:", ["Security", "Code Analysis"], default=["Security", "Code Analysis"])
                        
                        # Apply filters
                        filtered_findings = [f for f in findings if f.severity in severity_filter and f.agent in agent_filter]
                        
                        st.markdown(f"### 🔍 Filtered Findings ({len(filtered_findings)} / {len(findings)})")
                        
                        if filtered_findings:
                            for idx, finding in enumerate(filtered_findings, 1):
                                badge_color = "🔴" if finding.severity == "High" else "🟡"
                                line_str = f"Line {finding.line_number}" if finding.line_number else "General"
                                
                                with st.expander(f"{badge_color} [{finding.severity}] {finding.agent} - {line_str}: {finding.message[:50]}..."):
                                    st.write(f"**Category:** {finding.category}")
                                    st.write(f"**Description:** {finding.message}")
                                    if finding.cwe:
                                        st.write(f"**CWE:** {finding.cwe} | **OWASP:** {finding.owasp}")
                                    if finding.recommendation:
                                        st.info(f"**Remediation Advice:** {finding.recommendation}")
                                    
                                    # RAG Assistant Integration
                                    st.markdown("---")
                                    button_key = f"rag_assist_{idx}_{finding.line_number}_{finding.severity}"
                                    
                                    if st.button(f"🔍 Ask RAG Knowledge Base about {finding.cwe or 'this issue'}", key=button_key):
                                        rag_query = f"{finding.category} {finding.cwe or ''} secure coding remediation"
                                        st.session_state[f"rag_data_{button_key}"] = query_knowledge_base(rag_query, k=2)

                                    if f"rag_data_{button_key}" in st.session_state:
                                        rag_results = st.session_state[f"rag_data_{button_key}"]
                                        if rag_results:
                                            st.success("📚 **ChromaDB Vector Match Found:**")
                                            for r_idx, doc in enumerate(rag_results, 1):
                                                source_file = os.path.basename(doc.metadata.get('source', 'Security Standard'))
                                                st.markdown(f"**Source {r_idx} (`{source_file}`):**")
                                                st.info(doc.page_content)
                                        else:
                                            st.warning("No extra context found in the vector database.")
                        else:
                            st.info("No findings match the selected filter criteria.")
                    else:
                        st.balloons()
                        st.info("🎉 Excellent! No security vulnerabilities or code smells detected.")
        else:
            st.info("👈 Paste your code on the left and click **'Run SAST + Parallel Multi-Agent Analysis'** to begin.")
with tab2:
    st.subheader("📚 Secure Coding Knowledge Base (RAG Search)")
    user_query = st.text_input("Query OWASP standards, CWE guidelines, or secure coding rules:", placeholder="e.g., 'SQL Injection prevention', 'Hardcoded secrets'")
    
    if st.button("Search Knowledge Base", type="primary"):
        if user_query:
            results = query_knowledge_base(user_query, k=3)
            if results:
                seen = set()
                for idx, doc in enumerate(results, 1):
                    if doc.page_content not in seen:
                        seen.add(doc.page_content)
                        source_name = os.path.basename(doc.metadata.get('source', 'Unknown'))
                        with st.expander(f"Reference {idx} — Source: `{source_name}`"):
                            st.write(doc.page_content)
            else:
                st.info("No matching standards found in the vector database.")
        else:
            st.warning("Please enter a search query.")
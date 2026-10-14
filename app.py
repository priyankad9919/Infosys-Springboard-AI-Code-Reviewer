import streamlit as st
from src.validator import detect_and_validate
from src.rag_engine import query_knowledge_base

st.set_page_config(page_title="AI Code Reviewer - Module 1", layout="wide")

st.title("🛡️ AI Code Reviewer - Module 1 Dashboard")
st.caption("Code Submission, Syntax Validation & RAG Knowledge Base")

tab1, tab2 = st.tabs(["Code Submission Module", "RAG Knowledge Base Query"])

with tab1:
    st.subheader("Submit Code for Review")
    
    input_method = st.radio("Input Method", ["Paste Code", "Upload File"], horizontal=True)
    code_content = ""

    if input_method == "Paste Code":
        code_content = st.text_area("Paste code here (Language Auto-Detected):", height=250)
    else:
        uploaded_file = st.file_uploader("Upload .py or .java file", type=["py", "java"])
        if uploaded_file:
            code_content = uploaded_file.read().decode("utf-8")
            st.code(code_content)

    if st.button("Validate Submission"):
        if code_content.strip():
            result = detect_and_validate(code_content)
            if result.is_valid:
                st.success(f" Syntax Validation Passed! Detected Language: {result.language.capitalize()}")
            else:
                st.error(f"❌ {result.error_message}")
                if result.line_number:
                    st.warning(f"Error detected around line: {result.line_number}")
        else:
            st.warning("Please provide code before submitting.")

with tab2:
    st.subheader("Query Secure Coding Knowledge Base")
    user_query = st.text_input("Enter security topic (e.g., 'SQL Injection prevention', 'Hardcoded secrets')")
    
    if st.button("Search Knowledge Base"):
        if user_query:
            results = query_knowledge_base(user_query, k=3)
            if results:
                for idx, doc in enumerate(results, 1):
                    with st.expander(f"Result {idx} (Source: {doc.metadata.get('source', 'Unknown')})"):
                        st.write(doc.page_content)
            else:
                st.info("No matching standards found. Ensure database is indexed.")
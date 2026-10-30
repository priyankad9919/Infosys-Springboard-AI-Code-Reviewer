# 🛡️ AI Code Review & Security Analysis Agent

An intelligent, multi-agent automated code review and security analysis platform designed to eliminate vulnerabilities, catch code smells, and accelerate developer learning in real-time.

---

## 🌟 Project Overview

Software development teams frequently struggle with inconsistent code quality, undetected security vulnerabilities, and time-consuming manual code reviews. Developers often lack immediate access to expert guidance on secure coding practices, design principles, and vulnerability remediation during active development. Manual code reviews are slow, subjective, and unable to scale with growing codebases — leaving critical security risks and quality issues undetected until late in the development lifecycle.

The **AI Code Review & Security Analysis Agent** solves this by offering an intelligent platform that automatically analyzes source code for quality issues, security vulnerabilities, and best practice violations. Developers can paste code directly or upload source files in Python or Java to trigger an automated parallel multi-agent analysis pipeline.

---

## 🚀 Key Features & Capabilities

- **Multi-Language Syntax Validation:** Instant parsing and structural validation for Python (`ast`) and Java (`javalang`) source submissions.
- **Parallel Multi-Agent Orchestration:** Concurrent execution of specialized agents via `ThreadPoolExecutor` to optimize review performance.
- **OWASP Vulnerability & Code Smell Scanning:** Automated detection of top security risks (SQL Injection, Command Injection, hardcoded credentials/CWE-798, weak crypto/CWE-328) and quality smells (Java `==` string comparisons/CWE-476, Python `eval`/`exec`).
- **Security Quality Gate & Letter Grade Scorecard:** Automated repository health evaluation scoring codebases from A to F based on weighted severities.
- **RAG-Powered Secure Coding Knowledge Base:** Built-in semantic search engine indexed over comprehensive security standards (OWASP, Bandit, SpotBugs, Pylint) using local HuggingFace embeddings (`sentence-transformers/all-MiniLM-L6-v2`) and ChromaDB.
- **Interactive Developer Portal:** Built with Streamlit for a clean, intuitive, dark-themed dashboard featuring metric summary cards, interactive severity/agent filters, and persistent RAG query buttons.
- **Professional Report Generation:** Export findings instantly into **Executive PDF Review Reports** (via ReportLab) or **SARIF 2.1.0 Compliance JSON** for CI/CD and GitHub Actions integration.

---

## 🤖 Implemented Multi-Agent Architecture

1. **Security Vulnerability Agent:** Scans source code for OWASP-standard vulnerabilities, hardcoded secrets, injection flaws, and weak cryptography, applying severity scoring (High, Medium, Low).
2. **Code Analysis Agent:** Reviews code structure, design anti-patterns, complexity issues, and code smells (such as Java reference comparisons or unsafe built-ins).
3. **Orchestration Workflow (`workflow.py`):** Coordinates parallel threads, merges multi-agent outputs, and applies strict deduplication and line-grouping logic to ensure clean, clutter-free results.

---

## 📂 Project Architecture & Structure

ai-code-reviewer/
│
├── data/
│   └── knowledge_base/         # Markdown files for OWASP, Python, and Java security rules
├── chroma_db/                  # Persistent ChromaDB vector database files
├── src/
│   ├── __init__.py
│   ├── validator.py            # Syntax and structure validation logic for Python/Java
│   ├── rag_engine.py           # RAG ingestion, chunking, embedding, and semantic search
│   ├── workflow.py             # Parallel multi-agent orchestration and line-grouping engine
│   ├── models.py               # Pydantic data models for structured findings
│   ├── report_generator.py     # ReportLab executive PDF generation module
│   ├── sarif_exporter.py       # Industry-standard SARIF 2.1.0 compliance JSON exporter
│   └── agents/
│       ├── __init__.py
│       ├── security_agent.py   # Security vulnerability pattern scanner
│       └── code_analysis_agent.py # Code quality and smell analyzer
├── app.py                      # Main Streamlit dashboard interface
├── requirements.txt            # Project dependencies
└── README.md                   # Project documentation

---

## 🛠️ Tech Stack

- **Language:** Python 3.10+
- **UI Framework:** Streamlit
- **Orchestration & RAG:** LangChain (`langchain-text-splitters`, `langchain-community`, `langchain-huggingface`)
- **Vector Database:** ChromaDB (with SQLite persistence and HNSWlib indexing)
- **Embeddings:** HuggingFace (`sentence-transformers/all-MiniLM-L6-v2`)
- **Reporting:** ReportLab (PDF), JSON/SARIF (DevOps compliance)

---

## ⚙️ Installation & Setup

1. Clone the repository:
   ```bash
   git clone [https://github.com/your-username/ai-code-reviewer.git](https://github.com/your-username/ai-code-reviewer.git)
   cd ai-code-reviewer
2. Create and activate a virtual environment:
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
3. Install dependencies:
   pip install -r requirements.txt
4. Run Knowledge Base Ingestion:
   python src/rag_engine.py
5. Launch the Streamlit Dashboard:
   streamlit run app.py

## 📋 Roadmap & Milestones
# Milestone 1 (Completed):

-Studied OWASP vulnerability standards, secure coding guidelines, and local RAG architecture.

-Developed Code Submission Module supporting direct code paste and file upload for Python and Java with syntax validation.

-Built Secure Coding Knowledge Base — indexed OWASP guidelines and best practice documents into a RAG pipeline via markdown header chunking, local embeddings, and vector store persistence.

# Milestone 2 (Completed):

-Integrated parallel multi-agent orchestration pipeline (ThreadPoolExecutor) combining Security and Code Analysis agents.

-Implemented automated vulnerability severity scoring, line-grouping logic, and strict deduplication filters.

-Built Executive PDF Report generation (ReportLab) and SARIF 2.1.0 compliance JSON export modules.

-Upgraded Streamlit UI with metric cards, security letter grading (A-F), filter toolbars, and persistent RAG query buttons.

## 📄 License
This project is developed under academic and professional collaboration standards. All rights reserved.

# 🛡️ AI Code Review & Security Analysis Agent

An intelligent, multi-agent automated code review and security analysis platform designed to eliminate vulnerabilities, catch code smells, and accelerate developer learning in real-time.

---

## 🌟 Project Overview

Software development teams frequently struggle with inconsistent code quality, undetected security vulnerabilities, and time-consuming manual code reviews. Developers often lack immediate access to expert guidance on secure coding practices, design principles, and vulnerability remediation during active development. Manual code reviews are slow, subjective, and unable to scale with growing codebases — leaving critical security risks and quality issues undetected until late in the development lifecycle.

The **AI Code Review & Security Analysis Agent** solves this by offering an intelligent platform that automatically analyzes source code for quality issues, security vulnerabilities, and best practice violations. Developers can paste code directly or upload source files in **Python** or **Java** to trigger an automated analysis pipeline.

---

## 🚀 Key Features & Capabilities

* **Multi-Language Syntax Validation:** Instant parsing and validation for Python and Java source submissions.
* **OWASP Vulnerability Scanning:** Automated detection of top security risks including SQL Injection, XSS, hardcoded credentials, and broken access controls.
* **RAG-Powered Secure Coding Knowledge Base:** Built-in semantic search engine indexed over comprehensive security standards (OWASP, Bandit, SpotBugs, Pylint) using local HuggingFace embeddings (`sentence-transformers/all-MiniLM-L6-v2`) and ChromaDB.
* **Interactive Developer Portal:** Built with Streamlit for a clean, intuitive, and responsive multi-tab interface.
* **Contextual Q&A Assistant:** Allows developers to query secure coding principles and ask follow-up questions grounded directly in project knowledge documents.

---

## 🤖 Planned & Implemented Agents

1. **Code Analysis Agent:** Reviews code structure, identifies code smells, design anti-patterns, complexity issues, and poor practices.
2. **Security Vulnerability Agent:** Scans for OWASP-standard vulnerabilities with severity scoring.
3. **Remediation Agent:** Generates specific fix recommendations with corrected code examples.
4. **PR Summary Agent:** Compiles all agent findings into a structured, human-readable pull request style review summary.
5. **Conversational Code Assistant:** RAG-powered Q&A grounded in the secure coding knowledge base.

---

## 📂 Project Architecture & Structure

```text
ai-code-reviewer/
│
├── data/
│   └── knowledge_base/         # Markdown files for OWASP, Python, and Java security rules
├── chroma_db/                  # Persistent ChromaDB vector database files
├── src/
│   ├── __init__.py
│   ├── validator.py            # Syntax and structure validation logic for Python/Java
│   └── rag_engine.py           # RAG ingestion, chunking, embedding, and semantic search
├── app.py                      # Main Streamlit dashboard interface
├── requirements.txt            # Project dependencies
└── README.md                   # Project documentation
```

---

## 🛠️ Tech Stack

* **Language:** Python 3.10+
* **UI Framework:** Streamlit
* **Orchestration & RAG:** LangChain (`langchain-text-splitters`, `langchain-community`, `langchain-huggingface`)
* **Vector Database:** ChromaDB (with SQLite persistence and HNSWlib indexing)
* **Embeddings:** HuggingFace (`sentence-transformers/all-MiniLM-L6-v2`)

---

## ⚙️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/ai-code-reviewer.git
   cd ai-code-reviewer
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run Knowledge Base Ingestion (Milestone 1):**
   ```bash
   python src/rag_engine.py
   ```

5. **Launch the Streamlit Dashboard:**
   ```bash
   streamlit run app.py
   ```

---

## 📋 Roadmap & Milestones

* **Milestone 1 (Completed):** 
  * Study OWASP vulnerability standards, secure coding guidelines, and RAG architecture.
  * Develop Code Submission Module supporting direct code paste and file upload for Python and Java with syntax validation.
  * Build Secure Coding Knowledge Base — index OWASP guidelines and best practice documents into a RAG pipeline via markdown header chunking, local embeddings, and vector store persistence.
* **Milestone 2 (Upcoming):** Multi-agent orchestration pipeline integration, automated vulnerability severity scoring, and remediation report generation.

---

## 📄 License
This project is developed under academic and professional collaboration standards. All rights reserved.

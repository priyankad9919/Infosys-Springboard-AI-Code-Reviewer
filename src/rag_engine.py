import os
import streamlit as st
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

# Paths configuration
KB_DIRECTORY = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/knowledge_base"))
PERSIST_DIRECTORY = os.path.abspath(os.path.join(os.path.dirname(__file__), "../chroma_db"))

@st.cache_resource
def get_embedding_model():
    """Loads the model once and caches it in memory for instant subsequent queries."""
    return HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"}
    )

def ingest_knowledge_base():
    """
    Scans data/knowledge_base/ for markdown files, splits them into larger chunks (2000 chars),
    embeds them, and saves them into ChromaDB.
    """
    print(f"[*] Scanning knowledge base directory: {KB_DIRECTORY}")
    
    if not os.path.exists(KB_DIRECTORY):
        raise FileNotFoundError(f"Knowledge base directory not found at: {KB_DIRECTORY}")

    # 1. Load markdown files recursively
    loader = DirectoryLoader(
        KB_DIRECTORY,
        glob="**/*.md",
        loader_cls=TextLoader,
        loader_kwargs={"encoding": "utf-8"}
    )
    raw_documents = loader.load()
    print(f"[*] Loaded {len(raw_documents)} markdown files successfully.")

    # 2. Markdown Header Splitting (#, ##, ###)
    headers_to_split_on = [
        ("#", "Header 1"),
        ("##", "Header 2"),
        ("###", "Header 3"),
    ]
    markdown_splitter = MarkdownHeaderTextSplitter(headers_to_split_on=headers_to_split_on)
    
    header_split_docs = []
    for doc in raw_documents:
        splits = markdown_splitter.split_text(doc.page_content)
        for split in splits:
            split.metadata.update(doc.metadata)
            header_split_docs.append(split)

    # 3. Recursive Character Splitting with larger chunk size (2000 characters)
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=2000,   # Larger chunk size for more detailed output text
        chunk_overlap=300, # Smooth overlap for context continuity
        separators=["\n\n", "\n", " ", ""]
    )
    final_chunks = text_splitter.split_documents(header_split_docs)
    print(f"[*] Generated {len(final_chunks)} semantic chunks ready for embedding.")

    # 4. Embeddings & ChromaDB storage
    embeddings = get_embedding_model()
    
    print(f"[*] Indexing chunks into ChromaDB at: {PERSIST_DIRECTORY}")
    vector_store = Chroma.from_documents(
        documents=final_chunks,
        embedding=embeddings,
        persist_directory=PERSIST_DIRECTORY
    )
    
    print("[+] RAG Knowledge Base re-indexed successfully with larger chunks!")

def query_knowledge_base(query_text: str, k: int = 5):
    """
    Queries the persistent ChromaDB vector store.
    """
    print(f"[*] Querying RAG knowledge base for: '{query_text}'")
    
    embeddings = get_embedding_model()
    
    vector_store = Chroma(
        persist_directory=PERSIST_DIRECTORY,
        embedding_function=embeddings
    )
    
    results = vector_store.similarity_search(query_text, k=k)
    return results

# Allows you to run ingestion directly from terminal if needed
if __name__ == "__main__":
    ingest_knowledge_base()
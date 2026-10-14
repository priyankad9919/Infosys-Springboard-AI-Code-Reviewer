import os
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

CHROMA_PERSIST_DIR = "./chroma_db"
KNOWLEDGE_BASE_DIR = "./data/knowledge_base"

def initialize_vector_store():
    """Loads documents, splits into chunks, and saves embeddings to ChromaDB."""
    if not os.path.exists(KNOWLEDGE_BASE_DIR):
        os.makedirs(KNOWLEDGE_BASE_DIR, exist_ok=True)

    # 1. Load documents
    loader = DirectoryLoader(KNOWLEDGE_BASE_DIR, glob="**/*.md", loader_cls=TextLoader)
    documents = loader.load()

    if not documents:
        print("[!] No documents found in data/knowledge_base. Add .md files first.")
        return None

    # 2. Chunking
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=600,
        chunk_overlap=100,
        separators=["\n## ", "\n### ", "\n\n", "\n", " "]
    )
    docs = text_splitter.split_documents(documents)

    # 3. Embedding model using the updated package
    embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

    # 4. Vector store indexing using the updated package
    vector_db = Chroma.from_documents(
        documents=docs,
        embedding=embeddings,
        persist_directory=CHROMA_PERSIST_DIR
    )
    print(f"[+] Successfully indexed {len(docs)} chunks into ChromaDB at {CHROMA_PERSIST_DIR}")
    return vector_db

def query_knowledge_base(query: str, k: int = 3):
    """Retrieves top-k relevant security guidelines."""
    embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    vector_db = Chroma(persist_directory=CHROMA_PERSIST_DIR, embedding_function=embeddings)
    results = vector_db.similarity_search(query, k=k)
    return results

if __name__ == "__main__":
    initialize_vector_store()
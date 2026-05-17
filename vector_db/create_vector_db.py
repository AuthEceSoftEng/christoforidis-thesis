"""
Build the ChromaDB vector database from CodeQL documentation.

Creates two separate collections for retrieval-augmented generation (RAG):
  - codeql_queries: Indexed CodeQL query examples (.ql and .qll files)
  - codeql_documentation: Indexed documentation (.rst and .md files)

The vector database is used during query refinement to provide relevant
CodeQL documentation context to the LLM when it encounters compilation
errors or needs to implement new predicates.

Documents are split into overlapping character chunks before indexing (see
CHUNK_SIZE / CHUNK_OVERLAP constants). This keeps every chunk within the
embedding model's context window regardless of the original file size, and
improves retrieval precision by ensuring each chunk is semantically focused.

The database folder name is derived from the active EMBEDDING_MODEL so that
multiple embedding models can coexist on disk without overwriting each other
(e.g. vector_db/chroma_db_nomic-embed-text-v1.5/ vs chroma_db_bge-base-en-v1.5/).

When nomic-ai/* models are active, documents are prefixed with 'search_document:'
and queries with 'search_query:' as required by nomic-embed's task-instruction API.

The embedding model is read from the EMBEDDING_MODEL environment variable
(default: jinaai/jina-embeddings-v2-base-code). Set it via .env or inline:
    EMBEDDING_MODEL="nomic-ai/nomic-embed-text-v1.5" EMBEDDING_DEVICE="mps" \\
        python vector_db/create_vector_db.py
"""

import os
import glob
import logging
from tqdm import tqdm
import chromadb
from chromadb.utils import embedding_functions
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("vectordb.log"), logging.StreamHandler()]
)
logger = logging.getLogger('vectordb')

EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "jinaai/jina-embeddings-v2-base-code")
EMBEDDING_DEVICE = os.environ.get("EMBEDDING_DEVICE", "cpu")
IS_NOMIC = EMBEDDING_MODEL.startswith("nomic-ai/")
logger.info(f"Using embedding model: {EMBEDDING_MODEL}, device: {EMBEDDING_DEVICE}")

# Chunking parameters.
# Models with a 512-token window (e.g. bge-base-en-v1.5) silently truncate documents
# that exceed their limit, so chunking is not strictly required — they just lose content.
# Models with a large window (e.g. nomic-embed-text-v1.5 at 8192 tokens) try to process
# the full text, which causes OOM errors on files that are tens of thousands of tokens long.
# Chunking is therefore applied to ALL models for consistency: every model indexes the full
# content of every file, just split into overlapping pieces instead of one giant document.
#
# CHUNK_SIZE   — maximum characters per chunk (~375 tokens at 4 chars/token, well inside
#                any model's window and small enough to keep each chunk semantically focused)
# CHUNK_OVERLAP — characters shared between adjacent chunks to preserve context across
#                boundaries (e.g. a predicate definition that straddles a split point)
CHUNK_SIZE = 1500
CHUNK_OVERLAP = 200

def chunk_text(text, chunk_size=CHUNK_SIZE, overlap=CHUNK_OVERLAP):
    """
    Split text into overlapping fixed-size character chunks.

    Returns a list of strings. Files shorter than chunk_size are returned as-is
    (single-element list). Overlap ensures that context spanning a chunk boundary
    (e.g. a CodeQL predicate split across two chunks) is present in both neighbours.
    """
    if len(text) <= chunk_size:
        return [text]
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start += chunk_size - overlap
    return chunks

def load_documents(docs_dir):
    """
    Load and chunk text content from extracted documentation files.

    Each source file is split into overlapping character chunks (see CHUNK_SIZE /
    CHUNK_OVERLAP above). This keeps individual documents within the embedding
    model's context window regardless of the original file size, and improves
    retrieval precision by ensuring each chunk is semantically focused.

    Chunk metadata records the source file and the chunk index so retrieved
    results can be traced back to the original file.
    """
    logger.info(f"Loading documents from {docs_dir}")
    documents = []

    # Get all .txt files recursively
    txt_files = glob.glob(os.path.join(docs_dir, "**/*.txt"), recursive=True)
    logger.info(f"Found {len(txt_files)} text files")

    for file_path in txt_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()

            rel_path = os.path.relpath(file_path, docs_dir)
            file_name = os.path.basename(file_path)
            chunks = chunk_text(content)

            for i, chunk in enumerate(chunks):
                documents.append({
                    "content": chunk,
                    "metadata": {
                        "source": rel_path,
                        "file_path": file_path,
                        "file_name": file_name,
                        "chunk_index": i,
                        "total_chunks": len(chunks),
                    }
                })

        except Exception as e:
            logger.error(f"Error loading {file_path}: {str(e)}")

    logger.info(f"Successfully loaded {len(documents)} chunks from {len(txt_files)} files")
    return documents

def create_vector_db(db_path, model_name=None):
    """Initialize and return a ChromaDB collection."""
    model_name = model_name or EMBEDDING_MODEL
    # Create directories if they don't exist
    os.makedirs(db_path, exist_ok=True)

    # Initialize ChromaDB client
    client = chromadb.PersistentClient(path=db_path)

    # Create sentence transformer embedding function
    embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=model_name,
        device=EMBEDDING_DEVICE
    )
    
    # Create or get collection
    collection = client.get_or_create_collection(
        name="codeql_docs",
        embedding_function=embedding_function,
        metadata={"description": "CodeQL documentation collection"}
    )
    
    return collection

def create_categorized_vector_db(db_path, model_name=None):
    """Initialize and return ChromaDB collections for queries and documentation."""
    model_name = model_name or EMBEDDING_MODEL
    # Create directories if they don't exist
    os.makedirs(db_path, exist_ok=True)

    # Initialize ChromaDB client
    client = chromadb.PersistentClient(path=db_path)

    # Create sentence transformer embedding function
    embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=model_name,
        device=EMBEDDING_DEVICE
    )
    
    # Create separate collections
    query_collection = client.get_or_create_collection(
        name="codeql_queries",
        embedding_function=embedding_function,
        metadata={"description": "CodeQL query examples (.ql and .qll files)"}
    )
    
    docs_collection = client.get_or_create_collection(
        name="codeql_documentation", 
        embedding_function=embedding_function,
        metadata={"description": "CodeQL documentation (.rst and .md files)"}
    )
    
    return query_collection, docs_collection

def categorize_documents(documents):
    """Separate documents into queries and documentation based on original file extension.

    Key API-defining .qll files (DataFlow, Nodes, TaintTracking, AdditionalTaintSteps)
    are added to BOTH collections: as query examples AND as API reference documentation.
    This ensures the documentation collection returns actionable type/method information
    during the refinement correction loop, rather than only changelogs and blog posts.
    """
    query_docs = []
    doc_docs = []

    # QLL files whose content defines the core JS dataflow API that models need
    # during compile-error correction (wrong type names, wrong method signatures, etc.)
    API_REFERENCE_QLLS = {
        'DataFlow.qll.txt',
        'Nodes.qll.txt',
        'TaintTracking.qll.txt',
        'AdditionalTaintSteps.qll.txt',
        'AdditionalFlowStep.qll.txt',
        'DataFlowPrivate.qll.txt',
        'TaintTrackingPrivate.qll.txt',
    }

    for doc in documents:
        # Extract original extension from filename (before .txt was added)
        filename = doc['metadata']['file_name']

        # Check if it's a query file (.ql.txt or .qll.txt)
        if filename.endswith(('.ql.txt', '.qll.txt')):
            doc['metadata']['type'] = 'query'
            query_docs.append(doc)
            # Also index core API-defining QLL files into the documentation collection
            # so the correction loop can retrieve correct type/method definitions
            if filename in API_REFERENCE_QLLS:
                api_doc = dict(doc)
                api_doc['metadata'] = dict(doc['metadata'])
                api_doc['metadata']['type'] = 'documentation'
                doc_docs.append(api_doc)
        # Check if it's documentation (.rst.txt or .md.txt)
        elif filename.endswith(('.rst.txt', '.md.txt')):
            doc['metadata']['type'] = 'documentation'
            doc_docs.append(doc)
        else:
            # Default to documentation for any other files
            doc['metadata']['type'] = 'documentation'
            doc_docs.append(doc)

    return query_docs, doc_docs

def main():
    # Define paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    docs_dir = os.path.join(base_dir, "docs_txt")
    db_folder = "chroma_db_" + EMBEDDING_MODEL.split("/")[-1]
    db_path = os.path.join(base_dir, db_folder)
    
    # Load documents
    documents = load_documents(docs_dir)
    if not documents:
        logger.error("No documents loaded. Exiting.")
        return
    
    # Categorize documents
    query_docs, doc_docs = categorize_documents(documents)
    logger.info(f"Found {len(query_docs)} query files and {len(doc_docs)} documentation files")
    
    # Create vector databases
    query_collection, docs_collection = create_categorized_vector_db(db_path)
    
    # Add query documents to query collection
    if query_docs:
        logger.info("Adding query documents to vector database...")
        batch_size = 100
        for i in tqdm(range(0, len(query_docs), batch_size)):
            batch = query_docs[i:i+batch_size]
            
            ids = [f"query_{doc['metadata']['file_name']}_c{doc['metadata']['chunk_index']}" for doc in batch]
            documents = [
                f"search_document: {doc['content']}" if IS_NOMIC else doc["content"]
                for doc in batch
            ]
            metadatas = [doc["metadata"] for doc in batch]

            query_collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas
            )

    # Add documentation documents to docs collection
    if doc_docs:
        logger.info("Adding documentation to vector database...")
        batch_size = 100
        for i in tqdm(range(0, len(doc_docs), batch_size)):
            batch = doc_docs[i:i+batch_size]

            ids = [f"doc_{doc['metadata']['file_name']}_c{doc['metadata']['chunk_index']}" for doc in batch]
            documents = [
                f"search_document: {doc['content']}" if IS_NOMIC else doc["content"]
                for doc in batch
            ]
            metadatas = [doc["metadata"] for doc in batch]
            
            docs_collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas
            )
    
    logger.info(f"Successfully created vector database with {len(query_docs)} query chunks and {len(doc_docs)} documentation chunks")
    logger.info(f"Vector database created at {db_path}")

    ## ONE COLLECTION FOR ALL DOCUMENTS
    """ all_documents = documents  # Use complete documents
    
    logger.info(f"Using {len(all_documents)} complete documents")
    
    # Create vector database and collection
    collection = create_vector_db(db_path)
    
    # Add whole documents to collection
    logger.info("Adding documents to vector database...")
    batch_size = 100
    for i in tqdm(range(0, len(all_documents), batch_size)):
        batch = all_documents[i:i+batch_size]
        
        # Prepare batch data
        ids = [f"doc_{doc['metadata']['file_name']}" for doc in batch]
        documents = [doc["content"] for doc in batch]
        metadatas = [doc["metadata"] for doc in batch]
        
        # Add to collection
        collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas
        )
    
    logger.info(f"Successfully added {len(all_documents)} documents to vector database")
    logger.info(f"Vector database created at {db_path}") """

if __name__ == "__main__":
    main()
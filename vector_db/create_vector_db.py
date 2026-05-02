"""
Build the ChromaDB vector database from CodeQL documentation.

Creates two separate collections for retrieval-augmented generation (RAG):
  - codeql_queries: Indexed CodeQL query examples (.ql and .qll files)
  - codeql_documentation: Indexed documentation (.rst and .md files)

The vector database is used during query refinement to provide relevant
CodeQL documentation context to the LLM when it encounters compilation
errors or needs to implement new predicates.

Uses the 'all-MiniLM-L6-v2' SentenceTransformer model for embeddings.

Usage:
    python vector_db/create_vector_db.py
"""

import os
import glob
import logging
from tqdm import tqdm
import chromadb
from chromadb.utils import embedding_functions

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("vectordb.log"), logging.StreamHandler()]
)
logger = logging.getLogger('vectordb')

EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
EMBEDDING_DEVICE = os.environ.get("EMBEDDING_DEVICE", "cpu")
logger.info(f"Using embedding model: {EMBEDDING_MODEL}, device: {EMBEDDING_DEVICE}")

def load_documents(docs_dir):
    """Load text content from extracted documentation files."""
    logger.info(f"Loading documents from {docs_dir}")
    documents = []
    
    # Get all .txt files recursively
    txt_files = glob.glob(os.path.join(docs_dir, "**/*.txt"), recursive=True)
    logger.info(f"Found {len(txt_files)} text files")
    
    for file_path in txt_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                
                # Create relative path for metadata
                rel_path = os.path.relpath(file_path, docs_dir)
                
                documents.append({
                    "content": content,
                    "metadata": {
                        "source": rel_path,
                        "file_path": file_path,
                        "file_name": os.path.basename(file_path)
                    }
                })
                
        except Exception as e:
            logger.error(f"Error loading {file_path}: {str(e)}")
    
    logger.info(f"Successfully loaded {len(documents)} documents")
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
    """Separate documents into queries and documentation based on original file extension."""
    query_docs = []
    doc_docs = []
    
    for doc in documents:
        # Extract original extension from filename (before .txt was added)
        filename = doc['metadata']['file_name']
        
        # Check if it's a query file (.ql.txt or .qll.txt)
        if filename.endswith(('.ql.txt', '.qll.txt')):
            doc['metadata']['type'] = 'query'
            query_docs.append(doc)
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
    db_path = os.path.join(base_dir, "chroma_db")
    
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
            
            ids = [f"query_{doc['metadata']['file_name']}" for doc in batch]
            documents = [doc["content"] for doc in batch]
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
            
            ids = [f"doc_{doc['metadata']['file_name']}" for doc in batch]
            documents = [doc["content"] for doc in batch]
            metadatas = [doc["metadata"] for doc in batch]
            
            docs_collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas
            )
    
    logger.info(f"Successfully created vector database with {len(query_docs)} queries and {len(doc_docs)} docs")
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
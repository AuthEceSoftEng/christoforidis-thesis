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

device = "cpu"
logger.info(f"Using device: {device}")

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

def create_vector_db(db_path, model_name="all-MiniLM-L6-v2"):
    """Initialize and return a ChromaDB collection."""
    # Create directories if they don't exist
    os.makedirs(db_path, exist_ok=True)
    
    # Initialize ChromaDB client
    client = chromadb.PersistentClient(path=db_path)
    
    # Create sentence transformer embedding function
    embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=model_name, 
        device=device
    )
    
    # Create or get collection
    collection = client.get_or_create_collection(
        name="codeql_docs",
        embedding_function=embedding_function,
        metadata={"description": "CodeQL documentation collection"}
    )
    
    return collection

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
    
    all_documents = documents  # Use complete documents
    
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
    logger.info(f"Vector database created at {db_path}")

if __name__ == "__main__":
    main()
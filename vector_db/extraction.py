import re
import os
import logging
from io import StringIO
from bs4 import BeautifulSoup
from docutils.core import publish_parts

# Set up logger
def setup_logger(log_file='extraction.log'):
    """Set up a logger that writes to both console and a file."""
    # Create logger
    logger = logging.getLogger('extraction')
    logger.setLevel(logging.INFO)
    
    # Create handlers
    file_handler = logging.FileHandler(log_file)
    console_handler = logging.StreamHandler()
    
    # Create formatter and add it to handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Create logger
logger = setup_logger()

def extract_rst_content(file_path):
    """Extract content from RST files, handling includes gracefully."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Use docutils with file insertion disabled to prevent it from trying to handle includes itself
        settings = {
            'file_insertion_enabled': False,
            'warning_stream': StringIO(),
            'halt_level': 5  # Don't halt on warnings
        }
        
        parts = publish_parts(
            source=content,
            writer_name='html',
            settings_overrides=settings
        )
        
        # Extract and clean text from HTML
        html_body = parts['html_body']
        soup = BeautifulSoup(html_body, 'html.parser')
        text = soup.get_text(separator=' ')
        
        return text
    
    except Exception as e:
        logger.error(f"Error extracting content from {file_path}: {str(e)}")
        return None

def extract_text(file_path):
    """Extract text from .md, .ql, and .qll files."""
    logger.info(f"Extracting content from file: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        logger.info(f"Successfully extracted content from {file_path}")
        return content
    except Exception as e:
        logger.error(f"Error extracting content from {file_path}: {str(e)}")
        return None

def process_file(file_path):
    """Process a file based on its extension."""
    logger.info(f"Processing file: {file_path}")
    if file_path.endswith('.rst'):
        return extract_rst_content(file_path)
    elif file_path.endswith(('.md', '.ql', '.qll')):
        return extract_text(file_path)
    else:
        logger.info(f"Skipping unsupported file: {file_path}")
        return None

def save_extracted_text(file_path, content, output_folder):
    """Save extracted text into a .txt file."""
    if content is None:
        logger.warning(f"No content to save for {file_path}")
        return
        
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)
    logger.debug(f"Output folder ensured: {output_folder}")
    
    # Generate output file name
    base_name = os.path.basename(file_path)  # Get the original file name
    output_file = os.path.join(output_folder, f"{base_name}.txt")  # Append .txt extension
    
    # Save content to the file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"Saved extracted content to {output_file}")
    except Exception as e:
        logger.error(f"Error saving content to {output_file}: {str(e)}")

def extract_from_folder(folder_path, output_folder):
    """Recursively extract text from all files in a folder and save them."""
    logger.info(f"Starting extraction from folder: {folder_path}")
    file_count = 0
    processed_count = 0
    
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_count += 1
            file_path = os.path.join(root, file)
            logger.info(f"Found file: {file_path}")
            file_content = process_file(file_path)
            if file_content:
                processed_count += 1
                save_extracted_text(file_path, file_content, output_folder)
            else:
                print(file)
    
    logger.info(f"Extraction complete. Processed {processed_count} out of {file_count} files.")

if __name__ == "__main__":
    input_folder = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__))), "docs_original")
    output_folder = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__))), "docs_txt")
    logger.info(f"Starting extraction process from {input_folder} to {output_folder}")
    extract_from_folder(input_folder, output_folder)
    logger.info("Extraction process completed")
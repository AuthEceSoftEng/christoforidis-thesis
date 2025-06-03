import glob
import re
import os
import logging
import chromadb
from chromadb.utils import embedding_functions
from .LLM import LLMHandler
from .prompts import get_initial_sanitizer_prompt, get_refinement_sanitizer_prompt
from .query_runner import run_codeql_query_tables

# set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_codeql_package_classification(classified_methods, output_path):
    """
    Generate CodeQL library for package classifications.
    """
    # Count classifications
    sources = [m for m in classified_methods if m["classification"] == "SOURCE"]
    sinks = [m for m in classified_methods if m["classification"] == "SINK"]
    propagators = [m for m in classified_methods if m["classification"] == "PROPAGATOR"]
    
    logger.info(f"Found {len(sources)} SOURCE methods, {len(sinks)} SINK methods, and {len(propagators)} PROPAGATOR methods")
    
    with open(output_path, 'w') as f:
        # Write module header
        f.write("/**\n * @name Generated Package Classifications\n * @description CodeQL predicates for classified package methods\n */\n\n")
        f.write("import javascript\n")
        f.write("import DataFlow\n\n")
        
        # Write module declaration
        f.write("module VulnerableMethodsClassification {\n")
        
        # Define sources
        f.write("  /** Holds if the call is to a method classified as a SOURCE */\n")
        f.write("  predicate isVulnerableSource(DataFlow::CallNode call) {\n")
        f.write("    exists(string packageName, string methodName |\n")
        
        if sources:
            for i, method in enumerate(sources):
                package = method["package"]
                method_name = method["method"]
                f.write(f"      (packageName = \"{package}\" and methodName = \"{method_name}\")")
                if i < len(sources) - 1:
                    f.write(" or\n")
            f.write(" |\n")
        else:
            f.write("      none() |\n")
        
        f.write("      // Get the module import reference\n")
        f.write("      exists(DataFlow::SourceNode mod |\n")
        f.write("        mod = DataFlow::moduleImport(packageName) and\n")
        f.write("        call = mod.getAMemberCall(methodName)\n")
        f.write("      )\n")
        f.write("    )\n")
        f.write("  }\n\n")
        
        # Define sinks
        f.write("  /** Holds if the call is to a method classified as a SINK */\n")
        f.write("  predicate isVulnerableSink(DataFlow::CallNode call) {\n")
        f.write("    exists(string packageName, string methodName |\n")
        
        if sinks:
            for i, method in enumerate(sinks):
                package = method["package"]
                method_name = method["method"]
                f.write(f"      (packageName = \"{package}\" and methodName = \"{method_name}\")")
                if i < len(sinks) - 1:
                    f.write(" or\n")
            f.write(" |\n")
        else:
            f.write("      none() |\n")
        
        f.write("      // Get the module import reference\n")
        f.write("      exists(DataFlow::SourceNode mod |\n")
        f.write("        mod = DataFlow::moduleImport(packageName) and\n")
        f.write("        call = mod.getAMemberCall(methodName)\n")
        f.write("      )\n")
        f.write("    )\n")
        f.write("  }\n\n")
        
        # Define propagators
        f.write("  /** Holds if the call is to a method classified as a PROPAGATOR */\n")
        f.write("  predicate isVulnerablePropagator(DataFlow::CallNode call) {\n")
        f.write("    exists(string packageName, string methodName |\n")
        
        if propagators:
            for i, method in enumerate(propagators):
                package = method["package"]
                method_name = method["method"]
                f.write(f"      (packageName = \"{package}\" and methodName = \"{method_name}\")")
                if i < len(propagators) - 1:
                    f.write(" or\n")
            f.write(" |\n")
        else:
            f.write("      none() |\n")
        
        f.write("      // Get the module import reference\n")
        f.write("      exists(DataFlow::SourceNode mod |\n")
        f.write("        mod = DataFlow::moduleImport(packageName) and\n")
        f.write("        call = mod.getAMemberCall(methodName)\n")
        f.write("      )\n")
        f.write("    )\n")
        f.write("  }\n")
        
        # Close module
        f.write("}\n")

    logger.info(f"Successfully generated CodeQL library at {output_path}")

def _get_relevant_documentation(queries, collection):
    all_docs = {}

    for query in queries:
        results = collection.query(
            query_texts=[query],
            n_results=3
        )

        for i, (doc, metadata, distance) in enumerate(zip(
                results['documents'][0], 
                results['metadatas'][0], 
                results['distances'][0])):
            
            # deduplication
            key = doc[:100]
            if key not in all_docs:
                all_docs[key] = {
                    'content': doc,
                    'source': metadata.get('source', 'unknown'),
                    'distance': distance
                }

    # sort by relevance (distance)
    docs_text = ""
    sorted_docs = sorted(all_docs.values(), key=lambda x: x['distance'])
    top_docs = sorted_docs[:3]  # take top 5 most relevant documents

    for i, doc in enumerate(top_docs, 1):
        docs_text += f"\n--- DOCUMENT {i} (from {doc['source']}) ---\n{doc['content']}\n"

    return docs_text

def generate_conditional_sanitizer_library(classified_methods, output_path):
    """
    Generate a CodeQL library for conditional sanitizers with bypass detection predicates.
    
    Args:
        classified_methods: List of classified methods with bypass conditions
        output_path: Path to write the generated .qll library
        
    Returns:
        Path to the generated library or None if no sanitizers found
    """
    # Set up vector database connection
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, "vector_db", "chroma_db")

    database_path = os.path.join(base_dir, "databases", "juice-shop") # dummy codeql database to "run" the query , MUST EXIST
    
    embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2", 
        device="cpu"
    )
    
    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_collection(
        name="codeql_docs",
        embedding_function=embedding_function
    )

    # Extract conditional sanitizers
    conditional_sanitizers = [m for m in classified_methods if m["classification"] == "CONDITIONAL_SANITIZER"]
    logger.info(f"Found {len(conditional_sanitizers)} CONDITIONAL_SANITIZER methods")

    if not conditional_sanitizers:
        logger.info("No CONDITIONAL_SANITIZER methods found. Skipping library generation.")
        return None
    
    # Track predicate names to avoid duplicates by adding suffixes
    predicate_name_counts = {}
    
    # Add uniqueness counters to predicate names
    for sanitizer in conditional_sanitizers:
        package = sanitizer["package"]
        method = sanitizer["method"]
        base_name = f"is{package.replace('-', '_').title()}_{method}Bypassable"
        
        # If this is the first occurrence, use the base name
        if base_name not in predicate_name_counts:
            predicate_name_counts[base_name] = 1
            sanitizer["predicate_name"] = base_name
        else:
            # Otherwise add a counter suffix
            counter = predicate_name_counts[base_name]
            sanitizer["predicate_name"] = f"{base_name}_{counter}"
            predicate_name_counts[base_name] += 1
    
    # Initialize LLM handler
    llm_handler = LLMHandler('claude')
    
    with open(output_path, 'w') as f:
        # Write library header
        f.write("/**\n * @name Conditional Sanitizer Library\n * @description Predicates for detecting conditional sanitizers and their bypass conditions\n */\n\n")
        f.write("import javascript\n")
        f.write("import DataFlow\n\n")
        
        # Write module declaration with just the 3-argument predicate
        f.write("module ConditionalSanitizerLib {\n")
        f.write("  /** Holds if the call is to a specified package method classified as a CONDITIONAL_SANITIZER */\n")
        f.write("  predicate isConditionalSanitizer(DataFlow::CallNode call, string packageName, string methodName) {\n")
        f.write("    exists(DataFlow::SourceNode mod |\n")
        f.write("      (")
        
        # Write all package/method combinations directly in this predicate
        for i, sanitizer in enumerate(conditional_sanitizers):
            package = sanitizer["package"]
            method_name = sanitizer["method"]
            f.write(f"(packageName = \"{package}\" and methodName = \"{method_name}\")")
            if i < len(conditional_sanitizers) - 1:
                f.write(" or\n      ")
        
        f.write(") and\n")
        f.write("      mod = DataFlow::moduleImport(packageName) and\n")
        f.write("      call = mod.getAMemberCall(methodName)\n")
        f.write("    )\n")
        f.write("  }\n\n")

        for sanitizer in conditional_sanitizers:
            package = sanitizer["package"]
            method = sanitizer["method"]
            bypass_condition = sanitizer["bypass_condition"]
            predicate_name = sanitizer["predicate_name"]
            
            first_prompt = get_initial_sanitizer_prompt(sanitizer)
            
            messages = first_prompt
            
            try:
                initial_response = llm_handler.send_message(messages)
                logger.info(f"Generated initial predicate for sanitizer {sanitizer['predicate_name']}")

                test_query_path = os.path.join(os.path.dirname(output_path), f"test_{predicate_name}.ql")
                clean_response = generate_test_query_sanitizer(test_query_path, package, method, bypass_condition, initial_response, predicate_name)

                # run the test query to validate the predicate
                success, error = run_codeql_query_tables(database_path, test_query_path, os.path.dirname(output_path))
                tries = 0

                while not success and tries < 5:
                    clean_errors = extract_codeql_errors(error)
                    logger.error(f"Error running test query for sanitizer {sanitizer['predicate_name']}: {clean_errors}")

                    docs_text = _get_relevant_documentation([clean_errors], collection)
                    docs_text += _get_relevant_documentation([clean_response], collection)
                    messages.append({"role": "assistant", "message": clean_response})
                    messages.append(get_refinement_sanitizer_prompt(sanitizer, clean_response, docs_text, clean_errors)[0])

                    refined_response = llm_handler.send_message(messages)
                    logger.info(f"#Try: {tries+1}: Refined predicate for sanitizer {sanitizer['predicate_name']}")
                    clean_response = generate_test_query_sanitizer(test_query_path, package, method, bypass_condition, refined_response, predicate_name)
                    success, error = run_codeql_query_tables(database_path, test_query_path, os.path.dirname(output_path))
                    tries += 1


                # Write predicate header comment
                f.write(f"  /**\n")
                f.write(f"   * Holds if a call to {package}.{method} is potentially bypassable.\n")
                f.write(f"   * Bypass condition: {bypass_condition}\n")
                f.write(f"   */\n")
                
                # Write the predicate implementation
                f.write(clean_response)
                f.write("\n\n")

            except Exception as e:
                logger.error(f"Error processing sanitizer {sanitizer['predicate_name']}: {str(e)}")
                
                # Write fallback predicates for this sanitizer
                f.write(f"  /**\n")
                f.write(f"   * Holds if a call to {package}.{method} is potentially bypassable.\n")
                f.write(f"   * Bypass condition: {bypass_condition}\n")
                f.write(f"   */\n")
                f.write(f"  predicate {predicate_name}(DataFlow::CallNode call) {{\n")
                f.write(f"    // TODO: Implement detection for: {bypass_condition}\n")
                f.write(f"    isConditionalSanitizer(call, \"{package}\", \"{method}\") and\n")
                f.write(f"    exists(DataFlow::Node config |\n")
                f.write(f"      config = call.getArgument(0)\n")
                f.write(f"      // Add specific bypass condition detection here\n")
                f.write(f"    )\n")
                f.write(f"  }}\n\n")
                
        # Close module
        f.write("}\n")
    
    logger.info(f"Successfully generated conditional sanitizer library at {output_path}")
    return output_path

def clean_predicate_response(response):
    # Remove markdown code block markers if present
    if "```" in response:
        # Extract code from code blocks (handling various language tags)
        code_blocks = re.findall(r"```(?:ql|codeql|)?(.*?)```", response, re.DOTALL)
        if code_blocks:
            response = code_blocks[0].strip()
    
    # Find the actual predicate definition
    lines = response.split("\n")
    cleaned_lines = []
    in_predicate = False
    predicate_found = False
    
    for line in lines:
        line_stripped = line.strip()
        
        # Skip explanatory comments outside the predicate
        if line_stripped.startswith("//") and not in_predicate:
            continue
            
        # Skip explanatory text (not part of the predicate)
        if not in_predicate and not predicate_found and not line_stripped.startswith("predicate"):
            continue
            
        # Detect predicate start
        if "predicate" in line_stripped and "{" in line:
            in_predicate = True
            predicate_found = True
            cleaned_lines.append(line)
            continue
            
        # Inside predicate - add all lines
        if in_predicate:
            cleaned_lines.append(line)
            
            # Detect predicate end
            if line_stripped == "}":
                in_predicate = False
    
    # If we found a predicate definition, return just that
    if cleaned_lines:
        # Ensure proper indentation (two spaces for CodeQL)
        result = []
        for line in cleaned_lines:
            # Don't indent the predicate declaration line
            if "predicate" in line and "{" in line:
                result.append("  " + line.lstrip())
            # Indent everything else with proper nesting
            elif line.strip():
                # Add 2 spaces to existing indentation
                indent_level = len(line) - len(line.lstrip())
                result.append("  " + " " * indent_level + line.lstrip())
            else:
                result.append("")
                
        return "\n".join(result)
    
    # Fallback: if no clear predicate found, return the cleaned response
    return response.strip()

def extract_codeql_errors(error_string):
    if not error_string:
        return "No error information available"
    
    # Split into lines
    lines = error_string.strip().split('\n')
    
    # Extract only error messages
    error_messages = []
    for line in lines:
        if line.strip().startswith("ERROR:"):
            # Use regex to match the error message before the file path in parentheses
            import re
            match = re.match(r"ERROR:\s+(.*?)\s+\([^)]+\)$", line.strip())
            if match:
                error_messages.append(match.group(1))
            else:
                # Fallback: just remove the "ERROR:" prefix
                message = line.strip().replace("ERROR:", "", 1).strip()
                error_messages.append(message)
    
    # Deduplicate error messages
    unique_errors = []
    for msg in error_messages:
        if msg not in unique_errors:
            unique_errors.append(msg)
    
    return "\n".join(unique_errors)

def generate_test_query_sanitizer(test_query_path, package, method, bypass_condition, initial_response, predicate_name):
    with open(test_query_path, 'w') as test_f:
        test_f.write("/**\n * @name test\n * @description test\n * @kind table\n * @id js/test\n * @tags test\n */\n\n")
        test_f.write("import javascript\n")
        test_f.write("import DataFlow\n")
        test_f.write("/** Holds if the call is to a specified package method classified as a CONDITIONAL_SANITIZER */\n")
        test_f.write("predicate isConditionalSanitizer(DataFlow::CallNode call, string packageName, string methodName) {\n")
        test_f.write("  exists(DataFlow::SourceNode mod |\n")
        test_f.write("    (")
        test_f.write(f"(packageName = \"{package}\" and methodName = \"{method}\")")
        test_f.write(") and\n")
        test_f.write("      mod = DataFlow::moduleImport(packageName) and\n")
        test_f.write("      call = mod.getAMemberCall(methodName)\n")
        test_f.write("    )\n")
        test_f.write("  }\n\n")
        
    
        clean_response = clean_predicate_response(initial_response)

        # Write predicate header comment
        test_f.write(f"  /**\n")
        test_f.write(f"   * Holds if a call to {package}.{method} is potentially bypassable.\n")
        test_f.write(f"   * Bypass condition: {bypass_condition}\n")
        test_f.write(f"   */\n")
        
        # Write the predicate implementation
        test_f.write(clean_response)
        test_f.write("\n\n")

        # query to remove dummy error
        test_f.write("from DataFlow::CallNode call\n")
        test_f.write(f"where {predicate_name}(call)\n")
        test_f.write("select call")
    return clean_response

def cleanup_test_queries(dir):
    """
    Remove all test queries in the specified directory.
    """
    pattern = os.path.join(dir, "test_*.ql")
    test_files = glob.glob(pattern)
    count = 0
    
    for file in test_files:
        try:
            os.remove(file)
            count += 1
        except Exception as e:
            logger.error(f"Failed to remove test query file {file}: {str(e)}")

    logger.info(f"Removed {count} test query files from {dir}")
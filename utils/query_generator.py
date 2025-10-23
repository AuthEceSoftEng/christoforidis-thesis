import glob
import re
import os
import logging
import chromadb
from chromadb.utils import embedding_functions
from .LLM import LLMHandler
from .prompts import get_initial_sanitizer_prompt, get_refinement_sanitizer_prompt, get_sink_selection_prompt, flow_explaination_prompt, flow_implementation_prompt, flow_refinement_prompt, sink_explaination_prompt, sink_implementation_prompt, sink_refinement_prompt
from .query_runner import run_codeql_query_tables, run_codeql_path_problem
from .general import get_cwe_details, extract_predicate_from_file

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

    # Group sinks by CWE
    cwe_sinks = {}
    general_sinks = []
    
    for sink in sinks:
        if "cwes" in sink and sink["cwes"]:
            for cwe in sink["cwes"]:
                cwe_id = cwe["cwe_id"].replace("CWE-", "")
                if cwe_id not in cwe_sinks:
                    cwe_sinks[cwe_id] = []
                cwe_sinks[cwe_id].append(sink)
        else:
            general_sinks.append(sink)
    
    logger.info(f"Found {len(sources)} SOURCE methods, {len(sinks)} SINK methods, and {len(propagators)} PROPAGATOR methods")
    
    with open(output_path, 'w') as f:
        # Write module header
        f.write("/**\n * @name Generated Package Classifications\n * @description CodeQL predicates for classified package methods\n */\n\n")
        f.write("import javascript\n")
        f.write("import DataFlow\n\n")
        
        # Write module declaration
        f.write("module VulnerableMethodsClassificationLib {\n")
        
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
        # Generate generic sink predicate
        f.write("""  /** Holds if the call is to a method classified as a SINK */
  predicate isVulnerableSink(DataFlow::CallNode call) {
    exists(string packageName, string methodName |
""")
        all_sinks = [s for category in cwe_sinks.values() for s in category] + general_sinks
        if all_sinks:
            for i, sink in enumerate(all_sinks):
                or_str = " or" if i < len(all_sinks) - 1 else ""
                f.write(f'      (packageName = "{sink["package"]}" and methodName = "{sink["method"]}"){or_str}\n')
            f.write(" |\n")
        else:
            f.write("      none() |\n")
        f.write("""// Get the module import reference
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport(packageName) and
        call = mod.getAMemberCall(methodName)
      )
    )
  }

""")

        # Generate CWE-specific sink predicates
        for cwe_id, cwe_specific_sinks in cwe_sinks.items():
            cwe_name = cwe_specific_sinks[0]["cwes"][0]["name"].replace(" ", "")
            f.write(f"""  /** 
   * Holds if the call is to a method classified as a sink for CWE-{cwe_id} ({cwe_name})
   */
  predicate isCWE{cwe_id}Sink(DataFlow::CallNode call) {{
    exists(string packageName, string methodName |
""")
            for i, sink in enumerate(cwe_specific_sinks):
                or_str = " or" if i < len(cwe_specific_sinks) - 1 else ""
                f.write(f'      (packageName = "{sink["package"]}" and methodName = "{sink["method"]}"){or_str}\n')
            
            f.write("""      |
      // Get the module import reference
      exists(DataFlow::SourceNode mod |
        mod = DataFlow::moduleImport(packageName) and
        call = mod.getAMemberCall(methodName)
      )
    )
  }

""")
        
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
        
        f.write("\n  // propagator bridge predicate\n")
        f.write("  predicate propagates(DataFlow::Node pred, DataFlow::Node succ) {\n")
        f.write("    exists(DataFlow::CallNode call |\n")
        f.write("      isVulnerablePropagator(call) and\n")
        f.write("      (\n")
        f.write("        pred = call.getAnArgument() and\n")
        f.write("        succ = call\n")
        f.write("        or\n")
        f.write("        pred = call.getReceiver() and\n")
        f.write("        succ = call\n")
        f.write("      )\n")
        f.write("    )\n")
        f.write("  }\n\n")
        
        # Close module
        f.write("}\n")

    logger.info(f"Successfully generated CodeQL library at {output_path}")

def _get_relevant_documentation(queries, collection_type="both"):
    """Get relevant documentation from vector database."""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(base_dir, "vector_db", "chroma_db")
        
        client = chromadb.PersistentClient(path=db_path)
        embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2", device="cpu"
        )
        
        # Separate collections for queries and documentation
        query_docs = {}
        doc_docs = {}
        
        # Handle both single query string and list of queries
        if isinstance(queries, str):
            query_list = [queries]
        else:
            query_list = queries
        
        for query in query_list:
            # Get from query collection if requested
            if collection_type in ["both", "queries"]:
                try:
                    query_collection = client.get_collection(
                        name="codeql_queries",
                        embedding_function=embedding_function
                    )
                    query_results = query_collection.query(
                        query_texts=[query],
                        n_results=3
                    )
                    for i, (doc, metadata, distance) in enumerate(zip(
                            query_results['documents'][0], 
                            query_results['metadatas'][0], 
                            query_results['distances'][0])):
                        
                        # deduplication
                        key = doc[:100]
                        if key not in query_docs:
                            query_docs[key] = {
                                'content': doc,
                                'source': metadata.get('source', 'queries'),
                                'distance': distance,
                                'type': 'query'
                            }
                except Exception as e:
                    logger.warning(f"Could not access codeql_queries collection: {e}")
            
            # Get from documentation collection if requested
            if collection_type in ["both", "documentation"]:
                try:
                    docs_collection = client.get_collection(
                        name="codeql_documentation", 
                        embedding_function=embedding_function
                    )
                    doc_results = docs_collection.query(
                        query_texts=[query],
                        n_results=2
                    )
                    for i, (doc, metadata, distance) in enumerate(zip(
                            doc_results['documents'][0], 
                            doc_results['metadatas'][0], 
                            doc_results['distances'][0])):
                        
                        # deduplication
                        key = doc[:100]
                        if key not in doc_docs:
                            doc_docs[key] = {
                                'content': doc,
                                'source': metadata.get('source', 'documentation'),
                                'distance': distance,
                                'type': 'documentation'
                            }
                except Exception as e:
                    logger.warning(f"Could not access codeql_documentation collection: {e}")
            
            # Fallback to old single collection if new collections don't exist
            if not query_docs and not doc_docs:
                try:
                    collection = client.get_collection(
                        name="codeql_docs",
                        embedding_function=embedding_function
                    )
                    fallback_results = collection.query(
                        query_texts=[query],
                        n_results=3
                    )
                    all_docs = {}
                    for i, (doc, metadata, distance) in enumerate(zip(
                            fallback_results['documents'][0], 
                            fallback_results['metadatas'][0], 
                            fallback_results['distances'][0])):
                        
                        # deduplication
                        key = doc[:100]
                        if key not in all_docs:
                            all_docs[key] = {
                                'content': doc,
                                'source': metadata.get('source', 'unknown'),
                                'distance': distance,
                                'type': 'fallback'
                            }
                    
                    # Return fallback results
                    docs_text = ""
                    sorted_docs = sorted(all_docs.values(), key=lambda x: x['distance'])
                    top_docs = sorted_docs[:3]
                    
                    for i, doc in enumerate(top_docs, 1):
                        docs_text += f"\n--- DOCUMENT {i} (from {doc['source']}) ---\n{doc['content']}\n"
                    
                    return docs_text
                    
                except Exception as e:
                    logger.warning(f"Could not access fallback codeql_docs collection: {e}")

        # Sort each collection separately and take top 3 from each
        docs_text = ""
        doc_counter = 1
        
        # Add top 3 query documents
        if query_docs and collection_type in ["both", "queries"]:
            sorted_query_docs = sorted(query_docs.values(), key=lambda x: x['distance'])
            top_query_docs = sorted_query_docs[:3]
            
            for doc in top_query_docs:
                docs_text += f"\n--- QUERY DOCUMENT {doc_counter} (from {doc['source']}) ---\n{doc['content']}\n"
                doc_counter += 1
        
        # Add top 2 documentation documents  
        if doc_docs and collection_type in ["both", "documentation"]:
            sorted_doc_docs = sorted(doc_docs.values(), key=lambda x: x['distance'])
            top_doc_docs = sorted_doc_docs[:2]
            
            for doc in top_doc_docs:
                docs_text += f"\n--- DOCUMENTATION DOCUMENT {doc_counter} (from {doc['source']}) ---\n{doc['content']}\n"
                doc_counter += 1

        return docs_text
        
    except Exception as e:
        logger.error(f"Error querying vector database: {e}")
        return ""

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

    database_path = os.path.join(base_dir, "databases", "juice-shop") # dummy codeql database to "run" the query , MUST EXIST

    # Extract conditional sanitizers
    conditional_sanitizers = [m for m in classified_methods if m["classification"] == "CONDITIONAL_SANITIZER"]
    logger.info(f"Found {len(conditional_sanitizers)} CONDITIONAL_SANITIZER methods")

    if not conditional_sanitizers:
        logger.info("No CONDITIONAL_SANITIZER methods found. Skipping library generation.")
        with open(output_path, 'w') as f:
            f.write("""/**
                        * @name Conditional Sanitizer Library
                        * @description Predicates for detecting conditional sanitizers and their bypass conditions
                        */

                        import javascript
                        import DataFlow

                        module ConditionalSanitizerLib {
                        /** Holds if the call is to a specified package method classified as a CONDITIONAL_SANITIZER */
                        predicate isConditionalSanitizer(DataFlow::CallNode call, string packageName, string methodName) {
                            none()
                        }
                        }""")
        return None
    
    # Track predicate names to avoid duplicates by adding suffixes
    predicate_name_counts = {}
    
    # Add uniqueness counters to predicate names
    for sanitizer in conditional_sanitizers:
        package = sanitizer["package"]
        method = sanitizer["method"]
        base_name = "is"
        for cwe in sanitizer.get("cwes", []):
            if "cwe_id" in cwe:
                base_name += f"CWE_{cwe['cwe_id'].replace('CWE-', '')}_"
        base_name += f"{package.replace('-', '_').title()}_{method}"
        
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
    llm_handler = LLMHandler('claude', temperature=0.2)
    
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

                    docs_text = _get_relevant_documentation([clean_errors], "both")
                    docs_text += _get_relevant_documentation([clean_response], "both")
                    messages.append({"role": "assistant", "message": clean_response})
                    messages.append(get_refinement_sanitizer_prompt(sanitizer, clean_response, docs_text, clean_errors)[0])

                    refined_response = llm_handler.send_message(messages)
                    logger.info(f"#Try: {tries+1}: Refined predicate for sanitizer {sanitizer['predicate_name']}")
                    clean_response = generate_test_query_sanitizer(test_query_path, package, method, bypass_condition, refined_response, predicate_name)
                    success, error = run_codeql_query_tables(database_path, test_query_path, os.path.dirname(output_path))
                    tries += 1

                if success:
                    logger.info(f"Successfully validated predicate for sanitizer {sanitizer['predicate_name']}")
                    # Write predicate header comment
                    f.write(f"  /**\n")
                    f.write(f"   * Holds if a call to {package}.{method} is potentially bypassable.\n")
                    f.write(f"   * Bypass condition: {bypass_condition}\n")
                    f.write(f"   */\n")
                    
                    # Write the predicate implementation
                    f.write(clean_response)
                    f.write("\n\n")
                else:
                    logger.error(f"Failed to validate predicate for sanitizer {sanitizer['predicate_name']} after 5 tries")
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

def get_cwe_specific_sinks(cwe_id, project_name):
    llm = LLMHandler('claude', temperature=0.2)

    cwe_details = get_cwe_details(cwe_id)

    # get sinks from the isSink.qll
    sink_selection_prompt = get_sink_selection_prompt(cwe_details)
    sink_categories = llm.send_message(sink_selection_prompt).strip().split(',')
    sink_categories = [cat.strip() for cat in sink_categories]
    
    # get method sinks
    predicates = []
    pattern = re.compile(r"predicate\s+(isCWE(\d+)Sink)\s*\(")
    ql_file_path = os.path.join(os.path.dirname(__file__), "..", "codeql", "project_specific", project_name, "VulnerableMethodsClassification.qll")
    with open(ql_file_path, 'r') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                pred_name, pred_cwe_id = match.groups()
                if str(pred_cwe_id) == str(cwe_id):
                    predicates.append(pred_name)

    return {
        "classic_categories": sink_categories,
        "predicates": predicates,
    }

def get_cwe_specific_sanitizers(cwe_id, project_name):
    predicates = {}
    pattern = re.compile(r'predicate\s+(isCWE(?:_\d+)+_[A-Za-z0-9_]+)\s*\(')
    ql_file_path = os.path.join(os.path.dirname(__file__), "..", "codeql", "project_specific", project_name, "ConditionalSanitizers.qll")

    with open(ql_file_path, 'r') as f:
        content = f.read()
        for match in pattern.finditer(content):
            predicate_name = match.group(1)
            cwes = re.findall(r'CWE_(\d+)', predicate_name)
            for cwe in cwes:
                if cwe not in predicates:
                    predicates[cwe] = []
                predicates[cwe].append(predicate_name)

    return predicates.get(str(cwe_id), [])

def generate_vulnerability_query(cwe_id, project_name):
    sinks = get_cwe_specific_sinks(cwe_id, project_name)
    sanitizers = get_cwe_specific_sanitizers(cwe_id, project_name)

    sink_predicate_parts = []
    for category in sinks["classic_categories"]:
        sink_predicate_parts.append(f'{category.replace(" ", "")}(sink)')
    for pred in sinks['predicates']:
        sink_predicate_parts.append(f'exists(DataFlow::CallNode call | {pred}(call) and sink = call)')

    sink_predicate = f"""  predicate isSink(DataFlow::Node sink) {{
    {' or\n    '.join(sink_predicate_parts)}
  }}"""
    
    sanitizer_predicate_parts = []
    for pred in sanitizers:
        sanitizer_predicate_parts.append(f'ConditionalSanitizerLib::{pred}(call)')

    sanitizer_predicate = f"""predicate isBarrier(DataFlow::Node node) {{
    (TaintTracking::defaultSanitizer(node)
    or
    node instanceof TaintTracking::AdHocWhitelistCheckSanitizer
    or
    node instanceof TaintTracking::AdditionalBarrierGuard
    or
    node instanceof TaintTracking::InSanitizer
    or
    node instanceof TaintTracking::MembershipTestSanitizer
    or
    node instanceof TaintTracking::PositiveIndexOfSanitizer
    or
    node instanceof TaintTracking::WhitelistContainmentCallSanitizer
    or
    node instanceof TaintTracking::SanitizingRegExpTest)}}"""
    
    if sanitizer_predicate_parts:
        sanitizer_conditions = " or\n    ".join(sanitizer_predicate_parts)
        sanitizer_predicate = sanitizer_predicate[:-1]
        sanitizer_predicate +=f"""\n
    and not
    // Project-specific conditional sanitizers
    exists(DataFlow::CallNode call |
    (
    {sanitizer_conditions}
    ) and
    node = call
    )
  }}"""
        
    flow_predicate = f"""
    predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {{
        TaintTracking::defaultTaintStep(pred, succ)
        or
        TaintTracking::deserializeStep(pred, succ)
        or
        TaintTracking::heapStep(pred, succ)
        or
        TaintTracking::arrayStep(pred, succ)
        or
        TaintTracking::persistentStorageStep(pred, succ)
        or
        TaintTracking::promiseStep(pred, succ)
        or
        TaintTracking::serializeStep(pred, succ)
        or
        TaintTracking::sharedTaintStep(pred, succ)
        or
        TaintTracking::stringConcatenationStep(pred, succ)
        or
        TaintTracking::stringManipulationStep(pred, succ)
        or
        TaintTracking::uriStep(pred, succ)
        or
        TaintTracking::viewComponentStep(pred, succ)
        or
        exists(TaintTracking::AdditionalTaintStep additionalStep |
            additionalStep.step(pred, succ)
        )
        or
        exists(TaintTracking::SharedTaintStep additionalStep |
            additionalStep.step(pred, succ)
        )
        or
        exists(TaintTracking::StringConcatenationTaintStep additionalStep |
            additionalStep.step(pred, succ)
        )
        or
        exists(TaintTracking::UtilInspectTaintStep additionalStep |
            additionalStep.step(pred, succ)
        )
        or
        exists(TaintTracking::LegacyTaintStep additionalStep |
            additionalStep.step(pred, succ)
        )
        or
        exists(TaintTracking::ErrorConstructorTaintStep additionalStep |
            additionalStep.step(pred, succ)
        )
        or
        VulnerableMethodsClassificationLib::propagates(pred, succ)
    }}
    """
    
    query = general_vuln_query(cwe_id, sink_predicate, sanitizer_predicate, flow_predicate)

    output_path = os.path.join(os.path.dirname(__file__), "..", "codeql", "project_specific", project_name, f"cwe_{cwe_id}_vulnerability.ql")
    with open(output_path, 'w') as f:
        f.write(query)

    return [flow_predicate, sink_predicate, sanitizer_predicate, query]

def general_vuln_query(cwe_id, sink_predicate, sanitizer_predicate, flow_predicate):
    cwe_details = get_cwe_details(cwe_id)
    query = f"""/**
    * @name Vulnerability Query for CWE-{cwe_id}
    * @description This query identifies potential vulnerabilities related to CWE-{cwe_id} using custom sources, sinks, sanitizers, and propagators.
    * @kind path-problem
    * @problem.severity error
    * @precision high
    * @id js/cwe-{cwe_id}-vulnerability
    * @tags security
    */

    import javascript
    import DataFlow
    import isSource
    import isSink
    import VulnerableMethodsClassification
    import ConditionalSanitizers
    import CWE{cwe_details['id']}Flow::PathGraph

    /**
    * Configuration for {cwe_details['name']} vulnerabilities
    */
    module CWE{cwe_details['id']}Configuration implements DataFlow::ConfigSig {{
    predicate isSource(DataFlow::Node source) {{
        isSources(source)
        or
        exists(DataFlow::CallNode call |
            VulnerableMethodsClassificationLib::isVulnerableSource(call) and
            source = call
        )
    }}

    {sink_predicate}

    {sanitizer_predicate}

    {flow_predicate}

    }}

    // Create global taint tracking configuration
    module CWE{cwe_details['id']}Flow = TaintTracking::Global<CWE{cwe_details['id']}Configuration>;

    // Query
    from CWE{cwe_details['id']}Flow::PathNode source, CWE{cwe_details['id']}Flow::PathNode sink
    where CWE{cwe_details['id']}Flow::flowPath(source, sink)
    select sink.getNode(), source, sink, "{cwe_details['name']} vulnerability"
    """

    return query

def refine_sink_vulnerability_query(cwe_id, project_name, general: bool = False, extra_folder: str = None):
    sinks = get_cwe_specific_sinks(cwe_id, project_name)
    sinks = sinks['classic_categories']
    cwe_details = get_cwe_details(cwe_id)

    flow_predicate, sink_predicate, sanitizer_predicate, initial_query = generate_vulnerability_query(cwe_id, project_name)

    # Set up vector database connection
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    database_path = os.path.join(base_dir, "databases", project_name) # dummy codeql database to "run" the query , MUST EXIST
    
    vdb_queries_cwe = [f'{cwe_details["name"]}', f'{cwe_details["description"]}', f'CWE-{cwe_id}']
    #vdb_queries_sinks =['isSink', 'Sinks']
    docs = _get_relevant_documentation(vdb_queries_cwe, "both")
    #docs += _get_relevant_documentation(vdb_queries_sinks, "both")

    sinks_path = os.path.join(base_dir, "codeql", "isSink.qll")
    sinks_extracted = [extract_predicate_from_file(sinks_path, sink) for sink in sinks]

    llm = LLMHandler('claude', temperature=0.2)

    if not general:
        try:
            if extra_folder is None:
                readme_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', project_name, 'README.md')
            else:
                readme_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', extra_folder, project_name, 'README.md')
            with open(readme_path, 'r', encoding='utf-8') as file:
                readme_content = file.read()
        except FileNotFoundError:
            readme_content = "No README found for this project."

        try:
            if extra_folder is None:
                package_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', project_name, 'package.json')
            else:
                package_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', extra_folder, project_name, 'package.json')
            with open(package_path, 'r', encoding='utf-8') as file:
                package_content = file.read()
        except FileNotFoundError:
            package_content = "No package.json found for this project."
        messages = sink_explaination_prompt(cwe_details, sink_predicate, sinks_extracted, docs, readme_content, package_content)
    else:
        messages = sink_explaination_prompt(cwe_details, sink_predicate, sinks_extracted, docs)
    explanation = llm.send_message(messages)
    messages = sink_implementation_prompt(sink_predicate, explanation, docs)
    refined_sink_predicate = llm.send_message(messages)
    refined_sink_predicate = clean_predicate_response(refined_sink_predicate)
    query = general_vuln_query(cwe_id, refined_sink_predicate, sanitizer_predicate, flow_predicate)
    ql_path = os.path.join(base_dir, "codeql", "project_specific", project_name, f"cwe_{cwe_id}_vulnerability_sinkrefined.ql")

    with open(ql_path, 'w') as f:
        f.write(query)

    success, error = run_codeql_path_problem(database_path, ql_path, os.path.dirname(ql_path))
    tries = 0

    while not success and tries < 5:
        clean_errors = extract_codeql_errors(error)
        logger.error(f"Error running refined sink_predicate query for CWE-{cwe_id}: {clean_errors}")

        docs_text = _get_relevant_documentation([clean_errors], "both")
        docs_text += _get_relevant_documentation([refined_sink_predicate], "both")

        messages.append(sink_refinement_prompt(refined_sink_predicate, clean_errors, docs_text)[0])

        refined_sink_predicate = llm.send_message(messages)
        refined_sink_predicate = clean_predicate_response(refined_sink_predicate)

        logger.info(f"#Try: {tries+1}: Refined sink predicate for CWE-{cwe_id}")
        query = general_vuln_query(cwe_id, refined_sink_predicate, sanitizer_predicate, flow_predicate)
        with open(ql_path, 'w') as f:
            f.write(query)
        success, error = run_codeql_path_problem(database_path, ql_path, os.path.dirname(ql_path))

        tries += 1

    if success:
        logger.info(f"Successfully validated refined sink predicate for CWE-{cwe_id}")
        return refined_sink_predicate
    else:
        logger.error(f"Failed to validate refined sink predicate for CWE-{cwe_id} after 5 tries")
        with open(ql_path, 'w') as f:
            f.write(initial_query)
    return sink_predicate

def refine_flow_vulnerability_query(cwe_id, project_name, general: bool = False, extra_folder: str = None):
    sinks = get_cwe_specific_sinks(cwe_id, project_name)
    sinks = sinks['classic_categories']
    cwe_details = get_cwe_details(cwe_id)

    flow_predicate, sink_predicate, sanitizer_predicate, initial_query = generate_vulnerability_query(cwe_id, project_name)

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    database_path = os.path.join(base_dir, "databases", project_name) # dummy codeql database to "run" the query , MUST EXIST
    vdb_queries_cwe = [f'{cwe_details["name"]}', f'{cwe_details["description"]}', f'CWE-{cwe_id}']
    vdb_queries_taint_tracking = ['isAdditionalFlowStep', 'TaintTracking']
    docs = _get_relevant_documentation(vdb_queries_cwe, "both")
    docs += _get_relevant_documentation(vdb_queries_taint_tracking, "both")

    sinks_path = os.path.join(base_dir, "codeql", "isSink.qll")
    sinks_extracted = [extract_predicate_from_file(sinks_path, sink) for sink in sinks]

    llm = LLMHandler('claude', temperature=0.2)

    if not general:
        try:
            if extra_folder is None:
                readme_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', project_name, 'README.md')
            else:
                readme_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', extra_folder, project_name, 'README.md')
            with open(readme_path, 'r', encoding='utf-8') as file:
                readme_content = file.read()
        except FileNotFoundError:
            readme_content = "No README found for this project."

        try:
            if extra_folder is None:
                package_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', project_name, 'package.json')
            else:
                package_path = os.path.join(os.path.dirname(__file__), '..', 'codebases', extra_folder, project_name, 'package.json')
            with open(package_path, 'r', encoding='utf-8') as file:
                package_content = file.read()
        except FileNotFoundError:
            package_content = "No package.json found for this project."
        messages = flow_explaination_prompt(cwe_details, flow_predicate, sink_predicate, sinks_extracted, docs, readme_content, package_content)
    else:
        messages = flow_explaination_prompt(cwe_details, flow_predicate, sink_predicate, sinks_extracted, docs)
    explanation = llm.send_message(messages)
    messages = flow_implementation_prompt(flow_predicate, explanation, docs)
    refined_flow_predicate = llm.send_message(messages)
    refined_flow_predicate = clean_predicate_response(refined_flow_predicate)
    query = general_vuln_query(cwe_id, sink_predicate, sanitizer_predicate, refined_flow_predicate)
    ql_path = os.path.join(base_dir, "codeql", "project_specific", project_name, f"cwe_{cwe_id}_vulnerability_flowrefined.ql")

    with open(ql_path, 'w') as f:
        f.write(query)

    success, error = run_codeql_path_problem(database_path, ql_path, os.path.dirname(ql_path))
    tries = 0

    while not success and tries < 5:
        clean_errors = extract_codeql_errors(error)
        logger.error(f"Error running refined flow_predicate query for CWE-{cwe_id}: {clean_errors}")

        docs_text = _get_relevant_documentation([clean_errors], "both")
        docs_text += _get_relevant_documentation([refined_flow_predicate], "both")

        messages.append(flow_refinement_prompt(refined_flow_predicate, clean_errors, docs_text)[0])

        refined_flow_predicate = llm.send_message(messages)
        refined_flow_predicate = clean_predicate_response(refined_flow_predicate)

        logger.info(f"#Try: {tries+1}: Refined flow predicate for CWE-{cwe_id}")
        query = general_vuln_query(cwe_id, sink_predicate, sanitizer_predicate, refined_flow_predicate)
        with open(ql_path, 'w') as f:
            f.write(query)
        success, error = run_codeql_path_problem(database_path, ql_path, os.path.dirname(ql_path))

        tries += 1

    if success:
        logger.info(f"Successfully validated refined flow predicate for CWE-{cwe_id}")
        return [refined_flow_predicate, sanitizer_predicate]
    else:
        logger.error(f"Failed to validate refined flow predicate for CWE-{cwe_id} after 5 tries")
        with open(ql_path, 'w') as f:
            f.write(initial_query)
    return [flow_predicate, sanitizer_predicate]

def refine_vulnerability_query(cwe_id, project_name, general: bool = False, extra_folder: str = None):
    sink_predicate = refine_sink_vulnerability_query(cwe_id, project_name, general, extra_folder)
    flow_predicate, sanitizer_predicate = refine_flow_vulnerability_query(cwe_id, project_name, general, extra_folder)
    
    query = general_vuln_query(cwe_id, sink_predicate, sanitizer_predicate, flow_predicate)

    output_path = os.path.join(os.path.dirname(__file__), "..", "codeql", "project_specific", project_name, f"cwe_{cwe_id}_vulnerability_final_claude4new.ql")
    with open(output_path, 'w') as f:
        f.write(query)
    
    if general:
        general_path = os.path.join(os.path.dirname(__file__), "..", "codeql", "general", f"cwe_{cwe_id}_vulnerability_final.ql")
        os.makedirs(os.path.dirname(general_path), exist_ok=True)
        with open(general_path, 'w') as f:
            f.write(query)
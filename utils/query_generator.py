import logging

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
        
        # Define propagators (NEW)
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
    return output_path
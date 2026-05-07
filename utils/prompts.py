"""
LLM prompt templates for all stages of the vulnerability detection pipeline.

This module contains prompt-building functions that construct structured messages
for the LLM at each stage of the analysis:

  - Method classification (SOURCE/SINK/PROPAGATOR/CONDITIONAL_SANITIZER)
  - Conditional sanitizer predicate generation and refinement
  - Sink selection for specific CWEs
  - Two-phase sink and flow step refinement (explanation -> implementation)
  - CWE identification from project metadata
  - False positive confidence scoring
  - Call graph keyword filtering

Each function returns a list of message dicts with 'role' and 'message' keys,
ready to be passed to LLMHandler.send_message().
"""


def get_initial_sanitizer_prompt(sanitizer):
    """Build prompt for generating a CodeQL predicate to detect a bypassable conditional sanitizer."""
    package = sanitizer["package"]
    method = sanitizer["method"]
    bypass_condition = sanitizer["bypass_condition"]
    data_type = sanitizer.get("data_type", "data")
    predicate_name = sanitizer["predicate_name"]
    
    return [
        {
            "role": "user",
            "message": f"""You are a CodeQL expert specialized in security vulnerabilities for Javascript projects. Write a predicate to detect when a conditional sanitizer can be bypassed.

SANITIZER DETAILS:
Package: {package}
Method: {method}
Data Type: {data_type}
Bypass Condition: {bypass_condition}
Predicate Name: {predicate_name}

REQUIREMENTS:
1. Use EXACTLY the predicate name specified above
2. The predicate should take a DataFlow::CallNode parameter
3. First check that the call is to the right package/method using isConditionalSanitizer (takes call, "package-name", "methodName" as arguments)
4. Then analyze call arguments to detect the specific bypass condition
5. Write only the predicate code, properly formatted for a .qll file
6. Create public predicates only - DO NOT use the 'private' keyword
7. Predicate holds only when the vulnerable configuration is detected

Write only the predicate implementation without explanation.
DO NOT ADD ANY OTHER PREDICATES ONLY THE ONE REQUESTED.
"""
        }
    ]

def get_refinement_sanitizer_prompt(sanitizer, initial_predicate, docs_text, errors):
    """Build prompt for refining a sanitizer predicate after compilation errors."""
    package = sanitizer["package"]
    method = sanitizer["method"]
    bypass_condition = sanitizer["bypass_condition"]
    predicate_name = sanitizer["predicate_name"]

    return [
        {
            "role": "user",
            "message": f"""You are a CodeQL expert specialized in security vulnerabilities for Javascript projects. You previously wrote a predicate to detect when a conditional sanitizer can be bypassed:

SANITIZER DETAILS:
Package: {package}
Method: {method}
Bypass Condition: {bypass_condition}
Predicate Name: {predicate_name}

YOUR INITIAL IMPLEMENTATION:
{initial_predicate}

Errors in your implementation:
{errors}

Now I have relevant to the errors CodeQL documentation that might help improve this predicate:
{docs_text}

Please refine your predicate implementation based on this documentation. Focus on:

1. Correct usage of CodeQL syntax and patterns
2. Incorrect type access - make sure you're using the right methods for each type
3. Incorrect property access - verify property names exist on the types

REQUIREMENTS:
1. Use EXACTLY the predicate name specified above
2. The predicate should take a DataFlow::CallNode parameter
3. First check that the call is to the right package/method using isConditionalSanitizer (takes call, "package-name", "methodName" as arguments)
4. Then analyze call arguments to detect the specific bypass condition
5. Write only the predicate code, properly formatted for a .qll file
6. Create public predicates only - DO NOT use the 'private' keyword
7. Predicate holds only when the vulnerable configuration is detected

Write only the improved predicate code without explanation or commentary and extra reasoning.
DO NOT ADD ANY OTHER PREDICATES ONLY THE ONE REQUESTED.
""" } ]


def get_classifying_methods_prompt(package_name, version, method, advisory):
    """Build prompt for classifying an npm method as SOURCE/SINK/PROPAGATOR/CONDITIONAL_SANITIZER."""
    CLASSIFYING_METHODS_PROMPT = [
        {
            "role": "user",
            "message": """You are a security analyst trained to classify JavaScript methods from npm packages based on their role in taint analysis.

Your task is to classify a single method into one of four categories:

- **SOURCE**: Introduces untrusted or user-controlled input into the application.
- **SINK**: Accepts input where, if tainted, it can lead to a vulnerability (e.g., injection, denial of service).
- **CONDITIONAL_SANITIZER**: Attempts to validate or clean tainted input, but can fail if misconfigured.
- **PROPAGATOR**: Passes potentially tainted data without validating or sanitizing it.

Only one classification is allowed per method. Choose the best match based on the vulnerability summary and advisory details.

If you select **CONDITIONAL_SANITIZER**, explain what configuration or context causes the sanitizer to fail (BYPASS_CONDITION).

Also, specify what kind of data the method handles (DATA_TYPE), such as "HTTP body", "JWT token", or "Query string".

Focus your reasoning on how the method is commonly used in real-world applications and how the advisory describes its role in the vulnerability."""
        },
        {
            "role": "assistant",
            "message": "Understood. I will classify the method as requested, using the given structure."
        },
        {
            "role": "user",
            "message": f"""
Classify the following method for taint analysis:

- Package: {package_name} (v{version})
- Method: {method}
- Vulnerability Summary: {advisory['summary']}
- Advisory Details: {advisory['description']}

Respond using this format exactly:

CLASSIFICATION: [SOURCE | SINK | CONDITIONAL_SANITIZER | PROPAGATOR]
BYPASS_CONDITION: [If classification is CONDITIONAL_SANITIZER, describe what makes it fail; otherwise use "N/A"]
DATA_TYPE: [e.g., "HTTP body", "JWT token", "Query string"]
REASONING: [Brief explanation — max 3 sentences — why this method fits the classification]

Only provide the output in this format. Do not include any explanations or commentary outside this structure.
"""
        }
    ]

    return CLASSIFYING_METHODS_PROMPT

def get_sink_selection_prompt(cwe_details):
    """Build prompt for selecting relevant sink categories for a given CWE."""
    sink_selection_prompt = f"""
You are a security analyst tasked with selecting the most relevant sinks for a given CWE (Common Weakness Enumeration) vulnerability.
Select the appropriate sink categories from the following list for detecting the following CWE:
CWE ID: {cwe_details['id']}
CWE Name: {cwe_details['name']}
CWE Description: {cwe_details['description']}

Available Sink Categories:
- isCommandExecutionSink
- isDatabaseQuerySink
- isFileSystemSink
- isHttpResponseSink
- isDynamicCodeExecutionSink
- isDeserializationSink
- isLoggingSink
- isExternalApiSink
- isDomManipulationSink
- isOpenRedirectSink
- isXPathInjectionSink

Return only the selected sink categories in a comma-separated format without any additional text or explanation.
"""
    return [{"role": "user", "message": sink_selection_prompt}]

def flow_explaination_prompt(cwe_details, flow_predicate, sink_predicate, sinks_extracted, docs, readme_content=None, package_content=None, call_graph=None):
    """Build prompt for the explanation phase of flow step refinement (phase 1 of 2)."""
    prompt = f"""
    You are a CodeQL expert specialized in security vulnerabilities for Javascript projects. You are tasked with improving an isAdditionalFlowStep predicate in a custom configuration.
    The configuration tries to detect the following CWE (Common Weakness Enumeration) vulnerability.
    CWE ID: {cwe_details['id']}
    CWE Name: {cwe_details['name']}
    CWE Description: {cwe_details['description']}"""

    if readme_content is not None:
        prompt += f"""
        Project's README.md (summary):
        ```markdown
        {readme_content}
        ```
        """

    if package_content is not None:
        prompt += f"""
        Project's package.json:
        ```json
        {package_content}
        ```
        """

    if call_graph is not None:
        prompt += f"""
        
PROJECT CALL GRAPH (CWE-{cwe_details['id']} Relevant):
{call_graph}

This shows the actual function call relationships in this specific project, filtered for patterns relevant to {cwe_details['name']}.
Use this to identify:
- How data flows through THIS project's specific architecture
- Custom middleware, validators, or utility functions that propagate data
- Project-specific API patterns and abstractions
- Functions that connect user input (routes/handlers) to dangerous operations (sinks)
        """

    prompt += f"""
CURRENT IMPLEMENTATION:
    ```ql
    {flow_predicate}
    ```

    SINK DEFINITION:
    ```ql
    {sink_predicate}
    ```

    SINK PATTERNS DETECTED:
    ```ql
    {sinks_extracted}
    ```

    RELEVANT DOCUMENTATION:
    {docs}

    ANALYSIS TASK:
    1. First, analyze the sink definitions to identify exactly what types of vulnerabilities they represent
    2. Based ONLY on these sink definitions, identify the TOP 3 MOST CRITICAL missing flow patterns
    3. Prioritize patterns that would most improve detection of the specific vulnerability types in the sinks
    4. You should provide AT LEAST ONE missing flow pattern for each sink type
    5. If readme/package.json/call graph info is provided, use it to better understand the project context and refine your analysis
    6. Pay special attention to the call graph - it shows THIS project's actual data flow architecture
    
    For each pattern, provide:
    - A clear name and description of what's missing
    - Why it's critical for detection (high impact)
    - A simple code example showing a vulnerable pattern that would be missed
    - Reference specific functions/files from the call graph if relevant
    
    FOCUS: Your analysis must be based directly on the sink definitions provided and the actual call graph structure, not general assumptions about the CWE category.

    At this stage you should only focus on explaining the missing flow patterns and NOT on writing the actual CodeQL code.
"""
    
    return [{"role": "user", "message": prompt}]

def flow_implementation_prompt(flow_predicate, explanation, docs):
    """Build prompt for the implementation phase of flow step refinement (phase 2 of 2)."""
    prompt = f"""
    You are a CodeQL expert specialized in security vulnerabilities for Javascript projects. Based on your previous analysis of missing flow patterns:

    {explanation}

    I now need you to implement these improvements to the isAdditionalFlowStep predicate.

    CURRENT IMPLEMENTATION:
    ```ql
    {flow_predicate}
    ```

    RELEVANT DOCUMENTATION:
    {docs}

    IMPLEMENTATION TASK:
    1. Modify the predicate to include the missing flow patterns you identified
    2. Implement each pattern using correct CodeQL syntax and classes
    3. Add brief comments explaining each new pattern
    4. Ensure all existing functionality is preserved

    REQUIREMENTS:
    - Use only classes and methods available in the standard CodeQL JavaScript library
    - Follow CodeQL best practices for predicate implementation
    - Maintain proper indentation and formatting
    - Add ONLY the missing patterns - don't remove any existing functionality
    - Use clear, descriptive variable names

    Return the complete improved isAdditionalFlowStep predicate code without any explaination.
    """
    
    return [{"role": "user", "message": prompt}]

def flow_refinement_prompt(flow_predicate, errors, docs):
    """Build prompt for fixing compilation errors in a flow step predicate."""
    prompt = f"""
You are a CodeQL expert specialized in security vulnerabilities for Javascript projects. You previously wrote an improved predicate for missing flow patterns

YOUR INITIAL IMPLEMENTATION:
```ql
{flow_predicate}
```

ERRORS IN YOUR IMPLEMENTATION:
{errors}

RELEVANT DOCUMENTATION TO THE ERRORS:
{docs}

Please refine your predicate implementation based on this documentation. Focus on:

1. Correct usage of CodeQL syntax and patterns
2. Incorrect type access - make sure you're using the right methods for each type
3. Incorrect property access - verify property names exist on the types

Write only the improved predicate code without explanation or commentary and extra reasoning.
"""
    
    return [{"role": "user", "message": prompt}]

def decide_cwes_prompt(project_name: str, readme_content: str, package_content: str):
    """Build prompt for identifying applicable CWEs from project metadata."""
    prompt= f"""
You are a security analyst tasked with identifying all Common Weakness Enumerations (CWEs) we should try to detect for a given JavaScript project.

Output a comprehensive list of all CWE IDs that could plausibly apply to this project, including those related to insecure cryptographic practices, input validation, injection, or known library issues.
You may infer CWEs based on the project's functionality, libraries, or purpose.
Include all CWEs that are even moderately plausible, not just the most obvious ones.


### PROJECT NAME:
{project_name}

### README.md:
```markdown
{readme_content}
```

### package.json:
```json
{package_content}
```

Based on this information, return ONLY a list of applicable CWE IDs like this:
20, 79, 89
Do not include any other text or explanation.
"""
    return [{"role": "user", "message": prompt}]

def sink_explaination_prompt(cwe_details, sink_predicate, sinks_extracted, docs, readme_content=None, package_content=None, call_graph=None):
    """Build prompt for the explanation phase of sink refinement (phase 1 of 2)."""
    prompt = f"""
    You are a CodeQL expert specialized in security vulnerabilities for Javascript projects. You are tasked with improving an isSink predicate in a custom configuration.
    The configuration tries to detect the following CWE (Common Weakness Enumeration) vulnerability.
    CWE ID: {cwe_details['id']}
    CWE Name: {cwe_details['name']}
    CWE Description: {cwe_details['description']}"""

    if readme_content is not None:
        prompt += f"""
        Project's README.md (summary):
        ```markdown
        {readme_content}
        ```
        """

    if package_content is not None:
        prompt += f"""
        Project's package.json:
        ```json
        {package_content}
        ```
        """

    if call_graph is not None:
        prompt += f"""
        
PROJECT CALL GRAPH (CWE-{cwe_details['id']} Relevant):
{call_graph}

This shows the actual function call relationships in this specific project, filtered for patterns relevant to {cwe_details['name']}.
Use this to identify:
- Project-specific dangerous operations that may not be covered by standard sinks
- Custom database wrappers, file system utilities, or command execution functions
- Framework-specific APIs that this project uses (Express, Sequelize, etc.)
- Functions in routes/handlers/controllers that perform security-sensitive operations
        """

    prompt += f"""
CURRENT IMPLEMENTATION:
    ```ql
    {sink_predicate}
    ```

    SINK PATTERNS DETECTED:
    ```ql
    {sinks_extracted}
    ```

    RELEVANT DOCUMENTATION:
    {docs}

    ANALYSIS TASK:
    1. First, analyze the existing sink definitions and patterns detected
    2. Based on the CWE, identify the TOP 3 MOST CRITICAL missing sink patterns
    3. Prioritize patterns that would most improve detection of the specific vulnerability types
    4. If readme/package.json/call graph info is provided, use it to better understand the project context and refine your analysis
    5. Pay special attention to the call graph - it may reveal project-specific dangerous functions not covered by generic sinks
    
    For each pattern, provide:
    - A clear name and description of what's missing
    - Why it's critical for detection (high impact)
    - A simple code example showing a vulnerable pattern that would be missed
    - Reference specific functions/files from the call graph if they represent uncovered sinks

    FORMAT YOUR RESPONSE AS FOLLOWS:

    ## Missing Pattern 1: [Name]
    Description: [Clear description]
    Critical because: [Justification]
    Example:
    ```javascript
    // Code showing vulnerability
    
    At this stage you should only focus on explaining the missing sink patterns and NOT on writing the actual CodeQL code.
"""
    
    return [{"role": "user", "message": prompt}]

def sink_implementation_prompt(sink_predicate, explanation, docs):
    """Build prompt for the implementation phase of sink refinement (phase 2 of 2)."""
    prompt = f"""
    You are a CodeQL expert specialized in security vulnerabilities for Javascript projects. Based on your previous analysis of missing sink patterns:

    {explanation}

    I now need you to implement these improvements to the isSink predicate.

    CURRENT IMPLEMENTATION:
    ```ql
    {sink_predicate}
    ```

    RELEVANT DOCUMENTATION:
    {docs}

    IMPLEMENTATION TASK:
    1. Modify the predicate to include the missing sink patterns you identified
    2. Implement each pattern using correct CodeQL syntax and classes
    3. Add brief comments explaining each new pattern
    4. Ensure all existing functionality is preserved

    REQUIREMENTS:
    - Use only classes and methods available in the standard CodeQL JavaScript library
    - Follow CodeQL best practices for predicate implementation
    - Maintain proper indentation and formatting
    - Add ONLY the missing patterns - don't remove any existing functionality
    - Use clear, descriptive variable names

    Return the complete improved isSink predicate code without any explaination.
    DO NOT ADD ANY OTHER PREDICATES ONLY THE ONE REQUESTED.
    DO NOT ADD HELPER PRIVATE PREDICATES JUST ADD EVERYTHING INSIDE THE isSink PREDICATE.
    """
    
    return [{"role": "user", "message": prompt}]

def sink_refinement_prompt(sink_predicate, errors, docs):
    """Build prompt for fixing compilation errors in a sink predicate."""
    prompt = f"""
You are a CodeQL expert specialized in security vulnerabilities for Javascript projects. You previously wrote an improved predicate for missing sink patterns

YOUR INITIAL IMPLEMENTATION:
```ql
{sink_predicate}
```

ERRORS IN YOUR IMPLEMENTATION:
{errors}

RELEVANT DOCUMENTATION TO THE ERRORS:
{docs}

Please refine your predicate implementation based on this documentation. Focus on:

1. Correct usage of CodeQL syntax and patterns
2. Incorrect type access - make sure you're using the right methods for each type
3. Incorrect property access - verify property names exist on the types

Write only the improved predicate code without explanation or commentary and extra reasoning.
DO NOT ADD ANY OTHER PREDICATES ONLY THE ONE REQUESTED.
"""
    
    return [{"role": "user", "message": prompt}]

def keywords_filter_prompt(cwe_id, cwe_details):
    """Build prompt for identifying call graph filtering keywords relevant to a CWE."""
    keyword_prompt = [{
        "role": "user",
        "message": f"""You are analyzing a call graph to identify security-relevant function calls for a specific vulnerability type.

CWE-{cwe_id}: {cwe_details['name']}
Description: {cwe_details['description']}

Based on this vulnerability, identify 5-10 keywords that would appear in function/method names that are relevant to detecting this vulnerability.

For example:
- For SQL Injection: query, execute, find, sql, database, insert, update, delete
- For Command Injection: exec, spawn, command, shell, child_process
- For XSS: render, send, html, write, innerHTML

Focus on:
1. API functions commonly involved in this vulnerability
2. Method names that handle the vulnerable data type
3. Operations that could be dangerous if misused

Return ONLY a comma-separated list of keywords, nothing else.
Example output: query, execute, find, sql, database"""
    }]
    return keyword_prompt

def get_vulnerability_confidence(context, file_path, source_line, source_expression, sink_line, sink_expression, query_name, description, enriched_summary: str = ""):
    """Build prompt for assessing whether a detected vulnerability is a true positive or false positive."""
    prompt = f"""
You are a security analyst reviewing a code snippet to determine if it contains a vulnerability.
**Reported Vulnerability Type**: {query_name} - {description}
**Note**: This classification comes from static analysis and may be imprecise. Your job is to assess if ANY security vulnerability exists in the code, even if it's a different type than reported.

**File Path**: {file_path}

**Source Line**: {source_line} - {source_expression}
    Note: This may not be visible in the snippet if it's outside the context window.

**Sink Line**: {sink_line} - {sink_expression}
    Note: This may be the highlighted line (with →→→) in the snippet but is not necessarily the vulnerable line.

**Code Snippet/Context** (around the sink line):
```javascript
{context}
```
{f"""
**Semantic Summary** (extracted from inline comments and naming conventions):
{enriched_summary}
""" if enriched_summary else ""}
**Your Task**: Analyze the code snippet and determine if this is a TRUE vulnerability or a FALSE POSITIVE.

**Analysis Checklist:**
1. Is the source user-controlled input (req.body, req.query, req.params, etc.)?
2. Can you trace data flow from source to sink (or is sink using a variable that likely contains user input)?
3. Is there validation/sanitization between source and sink?
4. Is there any appropriate sanitization?

**Note**: The vulnerability type above is based on static analysis classification, which may not be 100% accurate. 
Focus on whether the CODE exhibits ANY security vulnerability, even if it doesn't exactly match the stated CWE type.
If you see a different vulnerability type (e.g., SQL injection when CWE-116 is stated), still rate it highly.
**Important**: If the code has a vulnerability but it's a different type than the reported CWE (e.g., XSS instead of Prototype Pollution), you should still rate it highly. Focus on whether the code is exploitable, not whether it matches the specific CWE.
This applies to ALL vulnerability types (injection, authentication bypass, information disclosure, etc.), not just these examples. Focus on whether the code is exploitable, not whether it matches the specific CWE label.

**Respond with ONLY this JSON (no markdown code blocks, no preamble):**
{{
  "confidence": <float 0.0-1.0>,
  "reasoning": "<brief explanation>",
  "verdict": "ASSESSMENT" | "INSUFFICIENT_CONTEXT"
}}

**Confidence Scale:**
- 0.85-1.0: Clear vulnerability. Direct unsanitized flow from user input to dangerous sink.
- 0.6-0.84: Likely vulnerable. Flow appears unsafe but minor uncertainty about context.
- 0.3-0.59: Uncertain. Sanitization may exist outside visible context or flow is unclear.
- 0.1-0.29: Likely false positive. Evidence of sanitization or safe usage.
- 0.0-0.09: Definitely false positive. Hard-coded values, test code, or properly sanitized.

**Verdict**:
- Use "ASSESSMENT" for normal cases where you can provide a confidence score.
- Use "INSUFFICIENT_CONTEXT" ONLY if critical code is missing (e.g., entire function is truncated) and you cannot make ANY assessment. In this case, set confidence to 0.5.
"""

    return [{"role": "user", "message": prompt}]


def enrich_context_prompt(raw_context: str, file_path: str, sink_line: int, query_name: str) -> list:
    """
    Build a prompt that asks the LLM to extract semantic intent from raw code context,
    leveraging inline comments, JSDoc annotations, and variable/function names.

    This is the first stage of the enriched-context pipeline (ablation study variant).
    The returned summary is then appended to the standard confidence prompt.

    Args:
        raw_context: The raw code slice around the sink (already highlighted with →→→).
        file_path: Source file path (for context).
        sink_line: Line number of the sink.
        query_name: Name of the CodeQL query that triggered this finding.

    Returns:
        Single-turn prompt list for LLMHandler.send_message().
    """
    prompt = f"""You are a senior security engineer reading source code.

**File**: {file_path}
**Sink line**: {sink_line}
**Reported issue**: {query_name}

**Code snippet** (the sink line is marked with →→→):
```javascript
{raw_context}
```

Your task is to produce a concise **semantic summary** of this code to help a colleague assess whether a reported vulnerability is real.

Extract and summarise:
1. **Function intent**: What is this function supposed to do? Use JSDoc comments, function names, and parameter names as evidence.
2. **Inline comments near the sink**: Are there any comments that explain what the highlighted line does, or that indicate sanitization / validation is happening?
3. **Data origin**: Based on variable names and comments, where does the data reaching the sink appear to come from (user input, config, hardcoded value, etc.)?
4. **Sanitization signals**: Are there any comments or naming conventions (e.g. `sanitized`, `escaped`, `validated`, `safe`) near the sink that suggest the data has been cleaned?

**Respond in plain text, 4–8 sentences maximum. Do not repeat the code. Do not speculate beyond what is visible.**
"""
    return [{"role": "user", "message": prompt}]
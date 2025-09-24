def get_initial_sanitizer_prompt(sanitizer):
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

def flow_explaination_prompt(cwe_details, flow_predicate, sink_predicate, sinks_extracted, docs, readme_content=None, package_content=None):
    prompt = f"""
    You are a CodeQL expert specialized in security vulnerabilities for Javascript projects. You are tasked with improving an isAdditionalFlowStep predicate in a custom configuration.
    The configuration tries to detect the following CWE (Common Weakness Enumeration) vulnerability.
    CWE ID: {cwe_details['id']}
    CWE Name: {cwe_details['name']}
    CWE Description: {cwe_details['description']}"""

    if readme_content is not None and package_content is not None:
        prompt += f"""
        Project's README.md (summary):
        ```markdown
        {readme_content}
        ```

        Project's package.json:
        ```json
        {package_content}
        ```
        """

    prompt += f"""CURRENT IMPLEMENTATION:
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
    
    For each pattern, provide:
    - A clear name and description of what's missing
    - Why it's critical for detection (high impact)
    - A simple code example showing a vulnerable pattern that would be missed
    
    FOCUS: Your analysis must be based directly on the sink definitions provided, not general assumptions about the CWE category.

    At this stage you should only focus on explaining the missing flow patterns and NOT on writing the actual CodeQL code.
"""
    
    return [{"role": "user", "message": prompt}]

def flow_implementation_prompt(flow_predicate, explanation, docs):
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
    prompt= f"""
You are a security analyst tasked with identifying all Common Weakness Enumerations (CWEs) we should try to detect for a given JavaScript project.

Output a comprehensive list of all CWE IDs that could plausibly apply to this project, including those related to insecure cryptographic practices, input validation, injection, or known library issues.
You may infer CWEs based on the project's functionality, libraries, or purpose.

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

def sink_explaination_prompt(cwe_details, sink_predicate, sinks_extracted, docs, readme_content=None, package_content=None):
    prompt = f"""
    You are a CodeQL expert specialized in security vulnerabilities for Javascript projects. You are tasked with improving an isSink predicate in a custom configuration.
    The configuration tries to detect the following CWE (Common Weakness Enumeration) vulnerability.
    CWE ID: {cwe_details['id']}
    CWE Name: {cwe_details['name']}
    CWE Description: {cwe_details['description']}"""

    if readme_content is not None and package_content is not None:
        prompt += f"""
        Project's README.md (summary):
        ```markdown
        {readme_content}
        ```

        Project's package.json:
        ```json
        {package_content}
        ```
        """

    prompt += f"""CURRENT IMPLEMENTATION:
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
    
    For each pattern, provide:
    - A clear name and description of what's missing
    - Why it's critical for detection (high impact)
    - A simple code example showing a vulnerable pattern that would be missed

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
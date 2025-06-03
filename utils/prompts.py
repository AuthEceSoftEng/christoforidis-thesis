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

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

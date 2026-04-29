# LLM-Augmented Static Analysis for JavaScript Vulnerability Detection

An automated security vulnerability detection system for JavaScript/Node.js applications that combines **GitHub CodeQL** (static analysis) with **Large Language Models** (Claude 3.7 Sonnet via AWS Bedrock) to dynamically generate, refine, and validate security queries.

The core innovation is using LLMs to:
- **Generate and refine CodeQL queries** tailored to each project based on CWE vulnerability types
- **Classify npm package methods** as sources, sinks, propagators, or conditional sanitizers
- **Filter false positives** from static analysis results using LLM-based confidence scoring
- **Decide which CWEs** to scan for based on project context (README, package.json, call graph)

---

## How It Works

1. **Clone** the target JavaScript repository at a specific commit
2. **Create a CodeQL database** from the source code
3. **Extract npm dependency method calls** via a CodeQL query
4. **Match dependencies against GitHub Security Advisories** to find known-vulnerable packages
5. **Classify each method** using an LLM as `SOURCE` / `SINK` / `PROPAGATOR` / `CONDITIONAL_SANITIZER`
6. **Generate CodeQL library files** (`.qll`) encoding the classified methods for use in queries
7. **Determine which CWEs to check** by combining LLM analysis of project metadata with advisory-derived CWEs
8. **Generate and iteratively refine vulnerability queries** using LLM + RAG over CodeQL documentation (up to 5 retry cycles with compiler error feedback)
9. **Run the final queries** against the CodeQL database to detect taint-flow vulnerability paths
10. **Filter results** using LLM-based confidence scoring to reduce false positives
11. **Evaluate** against ground truth data (precision, recall, F1)

---

## Architecture

```
Target JS Project
       |
       v
+------------------------+
| 1. Clone & Create DB   |  CodeQL database from source
+----------+-------------+
           |
           v
+----------------------------+
| 2. Extract Package Methods |  CodeQL query -> npm method calls
+----------+-----------------+
           |
           v
+------------------------------+
| 3. Match Against Advisories  |  GitHub Security Advisories API
+----------+-------------------+
           |
           v
+--------------------------------+
| 4. LLM Classifies Methods     |  SOURCE / SINK / SANITIZER / PROPAGATOR
+----------+---------------------+
           |
           v
+--------------------------------------+
| 5. Generate CodeQL Libraries (.qll)  |  + Conditional sanitizer predicates
+----------+---------------------------+
           |
           v
+----------------------------------+
| 6. Decide CWEs to Check         |  LLM + advisory CWEs
+----------+-----------------------+
           |
           v
+--------------------------------------+
| 7. Generate & Refine Queries         |  LLM + RAG (vector DB of CodeQL docs)
|    (iterative error correction)      |  Up to 5 retry cycles per predicate
+----------+---------------------------+
           |
           v
+------------------------------+
| 8. Run Final Queries (Batch) |  CodeQL path-problem analysis
+----------+-------------------+
           |
           v
+----------------------------------+
| 9. LLM False Positive Filtering |  Confidence scoring per finding
+----------+-----------------------+
           |
           v
+----------------------------------+
| 10. Evaluate Against Ground Truth |  Precision / Recall / F1
+----------------------------------+
```

---

## Directory Structure

```
.
├── README.md
├── requirements.txt
├── results_process.py              # Post-processing: combine/deduplicate CSV results
│
├── utils/                          # Core pipeline logic (Python)
│   ├── LLM.py                     # Multi-model LLM handler (Claude/GPT/Llama via Bedrock)
│   ├── prompts.py                 # All LLM prompt templates
│   ├── query_generator.py         # CodeQL query generation & LLM-based refinement
│   ├── query_runner.py            # CodeQL CLI wrapper (run queries, decode results)
│   ├── create_db.py               # CodeQL database creation from source code
│   ├── general.py                 # Utilities: file context, CWE API, call graph analysis
│   ├── cwe_decider.py             # Determines which CWEs to check
│   ├── methods_post_process.py    # Advisory comparison, method classification
│   ├── node_post_process.py       # Source/sink node deduplication and context extraction
│   ├── llm_filtering.py           # LLM-based false positive filtering
│   └── scraper.py                 # Clone repos, scrape OWASP CWE codes
│
├── codeql/                         # CodeQL queries & libraries
│   ├── qlpack.yml                  # CodeQL pack config (depends on codeql/javascript-all)
│   ├── registry.json               # CWE -> query mapping registry
│   ├── helpers.qll                 # Helper predicates
│   ├── isSink.qll                  # Comprehensive sink definitions (11 categories)
│   ├── isSource.qll                # Source definitions (HTTP, env vars, file reads, etc.)
│   ├── getSources.ql               # Query to extract all sources
│   ├── getSinks.ql                 # Query to extract all sinks
│   ├── getPackageMethods.ql        # Extract npm dependency method calls
│   ├── extractCallGraph.ql         # Extract function call relationships
│   ├── compat/                     # CWE compatibility layers (bridge files)
│   ├── default/                    # 100+ default security queries by CWE
│   └── project_specific/           # Generated per-project CodeQL libraries
│
├── vector_db/                      # RAG / Vector database for CodeQL documentation
│   ├── create_vector_db.py         # Build ChromaDB from CodeQL docs
│   ├── extraction.py               # Extract text from .md/.ql/.qll/.rst files
│   ├── chroma_db/                  # ChromaDB persistent storage
│   ├── docs_original/              # Raw CodeQL documentation
│   └── docs_txt/                   # Processed text files
│
├── evaluation_cves/                # CVE-based evaluation
│   ├── general_evaluator.py        # Full pipeline runner (simpler version)
│   ├── specific_evaluator.py       # Full pipeline with LLM/CodeQL timing stats
│   ├── all/                        # 200+ CVE JSON files (ground truth)
│   ├── mini_evaluation/            # 10-CVE subset for testing
│   ├── match_top10.py              # Match CVEs to OWASP Top 10
│   └── cwe_codes_top10.txt         # OWASP Top 10 CWE codes
│
├── vuln_apps_eval/                 # Vulnerable app evaluation
│   ├── evaluation.py               # Pipeline for known-vulnerable apps
│   ├── analyze_results.py          # Compare findings vs ground truth (TP/FP/FN)
│   ├── filter_results.py           # Apply confidence thresholds
│   ├── figures.py                  # Generate evaluation charts
│   ├── analyze_semgrep_results.py  # Compare with Semgrep
│   ├── analyze_njsscan_results.py  # Compare with njsscan
│   ├── compare_results.py          # Cross-tool comparison
│   ├── dvna/                       # DVNA evaluation data + ground truth
│   └── juice-shop/                 # Juice Shop evaluation data
│
├── codebases/                      # Target codebases to analyze (cloned here)
├── databases/                      # CodeQL databases (generated)
└── output/                         # Analysis output (CSV, SARIF, JSON)
```

---

## Prerequisites

- **Python 3.10+**
- **CodeQL CLI** - installed and available on `PATH` ([installation guide](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli))
- **GitHub CLI (`gh`)** - for fetching security advisories ([installation guide](https://cli.github.com/))
- **AWS Account** with Bedrock access to Claude 3.7 Sonnet and Llama 3.2 models (eu-central-1 region)
- **Git**

---

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd christoforidis-thesis
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate        # Linux/macOS
   # .venv\Scripts\activate         # Windows
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**

   Create a `.env` file in the project root:
   ```env
   ACCOUNT_ID=<your-aws-account-id>
   # OPENAI_API_KEY=<your-openai-key>    # Optional, for GPT-4o support
   ```

5. **Configure AWS credentials:**

   Ensure your AWS credentials are configured (via `~/.aws/credentials`, environment variables, or IAM role) with access to Bedrock in `eu-central-1`.

6. **Install CodeQL packs:**
   ```bash
   cd codeql
   codeql pack install
   cd ..
   ```

---

## Usage

### 1. Build the Vector Database (one-time setup)

Extract CodeQL documentation and build the ChromaDB vector database used for RAG:

```bash
# First, place CodeQL documentation files in vector_db/docs_original/
python vector_db/extraction.py           # Extract text from docs
python vector_db/create_vector_db.py     # Build ChromaDB index
```

### 2. Run the CVE-Based Evaluation Pipeline

Evaluates the system against real-world CVEs with known vulnerable commits:

```bash
# Run the full pipeline with detailed timing statistics
python evaluation_cves/specific_evaluator.py
```

This will:
- Clone repositories at pre-patch commits
- Create CodeQL databases
- Extract and classify methods
- Generate and refine vulnerability queries
- Run queries and collect results
- Output timing/token statistics to `output/reports/`

### 3. Run the Vulnerable Apps Evaluation

Evaluates the system against intentionally vulnerable applications (DVNA, Juice Shop):

```bash
# Place the target app source code in codebases/<app-name>/
python vuln_apps_eval/evaluation.py
```

### 4. Analyze Results Against Ground Truth

Compare detection results against known vulnerabilities:

```bash
python vuln_apps_eval/analyze_results.py <csv_results_file> <ground_truth.json> [output.json]

# Example:
python vuln_apps_eval/analyze_results.py output/dvna/results.csv vuln_apps_eval/dvna/vulns.json results.json
```

### 5. Apply LLM-Based Filtering

Filter results at various confidence thresholds:

```bash
python vuln_apps_eval/filter_results.py
```

### 6. Post-Process and Deduplicate Results

Combine and deduplicate CSV result files from multiple runs:

```bash
python results_process.py
```

> **Note:** Edit the `parent_dir` path in `results_process.py` to point to your output directory before running.

---

## Technology Stack

| Technology | Role |
|---|---|
| **Python** | Primary orchestration language |
| **CodeQL (QL)** | Static analysis query language for vulnerability detection |
| **AWS Bedrock** | LLM inference (Claude 3.7 Sonnet, Llama 3.2) |
| **ChromaDB** | Vector database for RAG over CodeQL documentation |
| **SentenceTransformers** | Embedding model (`all-MiniLM-L6-v2`) for vector similarity |
| **pandas** | Data manipulation for CSV/DataFrame processing |
| **esprima** | JavaScript AST parsing for smart context extraction |
| **semver** | Semantic version comparison for vulnerability range matching |
| **fuzzywuzzy** | Fuzzy string matching for deduplicating sanitizer conditions |
| **BeautifulSoup** | Web scraping (OWASP CWE codes) |

---

## Evaluation

The project supports two evaluation strategies:

1. **CVE-Based Evaluation:** 200+ real CVEs with known vulnerable commits. Clones repos at pre-patch state, runs the full pipeline, and checks if vulnerabilities are detected at the correct file/line.

2. **Vulnerable App Evaluation:** Tests against intentionally vulnerable applications (DVNA with 14 known vulns, OWASP Juice Shop) with manually created ground truth JSON files. Computes precision, recall, and F1 score, and compares against Semgrep and njsscan.

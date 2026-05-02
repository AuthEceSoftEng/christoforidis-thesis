# Clean Run Guide

This document describes every step required to get the project running from a fresh clone. Follow the steps in order — each one is a prerequisite for the next.

---

## Prerequisites

Make sure the following are installed and available on your `PATH` before starting:

| Tool | Purpose | Install guide |
|---|---|---|
| **Python 3.10+** | Runtime for all pipeline scripts | [python.org](https://www.python.org/downloads/) |
| **CodeQL CLI** | Static analysis engine | [GitHub docs](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli) |
| **GitHub CLI (`gh`)** | Fetching GitHub Security Advisories | [cli.github.com](https://cli.github.com/) |
| **Git** | Cloning repos | [git-scm.com](https://git-scm.com/) |

Verify they are available:

```bash
python3 --version
codeql --version
gh --version
git --version
```

---

## Step 1 — Clone and set up the Python environment

```bash
git clone <repository-url>
cd christoforidis-thesis

python3 -m venv .venv
source .venv/bin/activate       # macOS/Linux
# .venv\Scripts\activate        # Windows

pip install -r requirements.txt
```

> All subsequent commands assume the virtual environment is active. Run `source .venv/bin/activate` again if you open a new terminal.

---

## Step 2 — Configure environment variables

Create a `.env` file in the project root with your API credentials:

```env
ARIADNE_API_KEY=sk-proj-YOUR-TOKEN-HERE
ARIADNE_BASE_URL=https://ariadne.issel.ee.auth.gr/api/v1
ARIADNE_MODEL_ID=claude-sonnet-4
ARIADNE_PROVIDER=gcp
```

> The `.env` file is gitignored and must be created manually on every fresh clone.

---

## Step 3 — Install CodeQL packs

The pipeline's queries live in the `codeql/` folder and depend on `codeql/javascript-all` (the official CodeQL JS/TS standard library). Install the declared dependencies with:

```bash
cd codeql
codeql pack install
cd ..
```

This downloads the required packs (e.g. `codeql/javascript-all`, `codeql/dataflow`, etc.) from the CodeQL package registry into `~/.codeql/packages/`, where the CodeQL CLI will find them automatically at query runtime.

> **Note:** The `vector_db/docs_original/` folder also contains a copy of the `codeql/javascript-all` source (used only as text for the vector DB). Do not confuse it with the functional library installed here — they serve entirely different purposes.

---

## Step 4 — Build the Vector Database

The vector DB is a ChromaDB instance that the LLM queries at runtime (via RAG) when generating and refining CodeQL queries. It is built from the JavaScript/TypeScript section of the official [github/codeql](https://github.com/github/codeql) repository and must be rebuilt on every fresh clone (its contents are gitignored).

### 4a — Populate `docs_original/`

You need a local copy of the `javascript/` folder from the `github/codeql` repository. This folder covers both JavaScript and TypeScript — no other language folder is needed.

**If you already have the repo cloned locally:**
```bash
cp -r /path/to/codeql-repo/javascript/. vector_db/docs_original/
```

**If you don't have it yet:**
```bash
git clone https://github.com/github/codeql /tmp/codeql-repo
cp -r /tmp/codeql-repo/javascript/. vector_db/docs_original/
```

### 4b — Extract and clean text

```bash
python vector_db/extraction.py
```

Reads `.ql`, `.qll`, `.md`, and `.rst` files from `docs_original/`, strips URLs and excess whitespace, and saves the cleaned content as `.txt` files in `docs_txt/`. Logs are written to `extraction.log`.

### 4c — Embed and index into ChromaDB

```bash
python vector_db/create_vector_db.py
```

Embeds all files from `docs_txt/` and writes the ChromaDB vector database to `chroma_db/`. Two collections are created:

| Collection | Contents | ~Size |
|---|---|---|
| `codeql_queries` | `.ql` and `.qll` files | ~1,300 documents |
| `codeql_documentation` | `.md` and `.rst` files | ~270 documents |

Logs are written to `vectordb.log`.

---

## Ready-state checklist

| Component | Status after setup |
|---|---|
| Python virtual environment | Active, all dependencies installed |
| `.env` with API credentials | Present in project root |
| CodeQL packs | Downloaded to `~/.codeql/packages/` |
| Vector DB (ChromaDB) | Built and indexed in `vector_db/chroma_db/` |

## Clone the repo 

Clone the repository you wanna check to codebases/


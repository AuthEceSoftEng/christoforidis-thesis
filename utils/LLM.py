"""
LLM handler for interacting with the Ariadne API.

Provides a unified `LLMHandler` class that formats messages and calls the
Ariadne /api/v1/messages endpoint. Also includes global and per-project
statistics tracking (request count, timing, token estimation) for
performance analysis during evaluation runs.

Environment Variables (all required — set in .env):
    ARIADNE_API_KEY:   Bearer token for the Ariadne API.
    ARIADNE_BASE_URL:  Base URL of the Ariadne API including /v1
                       (e.g. https://ariadne.issel.ee.auth.gr/api/v1).
    ARIADNE_MODEL_ID:  Model ID to use in requests (e.g. claude-sonnet-4).
    ARIADNE_PROVIDER:  Provider name to use in requests (e.g. gcp).
"""

import os
import sys
import time
import requests # type: ignore
from dotenv import load_dotenv # type: ignore
from collections import defaultdict


class InsufficientCreditsError(Exception):
    """
    Raised when the Ariadne API returns HTTP 402 (Payment Required).

    This indicates the account has run out of credits. The pipeline catches
    this exception at the top level, logs the freeze point, and exits with
    code 2. Re-running the same command will automatically resume from the
    last on-disk checkpoint — no completed work is lost.
    """
    pass

load_dotenv()

# Global tracking variables
_current_project = None
_global_stats = {
    'request_count': 0,
    'total_request_time': 0.0,
    'total_input_tokens': 0,
    'total_output_tokens': 0,
    'request_history': []
}
_project_stats = defaultdict(lambda: {
    'request_count': 0,
    'total_request_time': 0.0,
    'total_input_tokens': 0,
    'total_output_tokens': 0,
    'request_history': []
})

def _estimate_tokens(text):
    """Rough token estimation (4 chars ≈ 1 token)"""
    return len(str(text)) // 4


def _extract_input_text(messages):
    """Extract text from messages for token counting"""
    if isinstance(messages, list):
        return " ".join([m.get("message", "") for m in messages if isinstance(m, dict)])
    return str(messages)

def _track_request(model, input_text, output_text, request_time):
    """Track a single request's statistics"""
    global _global_stats, _project_stats, _current_project

    input_tokens = _estimate_tokens(input_text)
    output_tokens = _estimate_tokens(output_text)

    # Update global totals
    _global_stats['request_count'] += 1
    _global_stats['total_request_time'] += request_time
    _global_stats['total_input_tokens'] += input_tokens
    _global_stats['total_output_tokens'] += output_tokens

    # Store global request details
    request_info = {
        'project': _current_project,
        'timestamp': time.time(),
        'request_time': request_time,
        'input_tokens': input_tokens,
        'output_tokens': output_tokens,
        'model': model
    }
    _global_stats['request_history'].append(request_info)

    # Update project-specific stats if project is set
    if _current_project:
        project_stats = _project_stats[_current_project]
        project_stats['request_count'] += 1
        project_stats['total_request_time'] += request_time
        project_stats['total_input_tokens'] += input_tokens
        project_stats['total_output_tokens'] += output_tokens
        project_stats['request_history'].append(request_info)

class LLMHandler:
    def __init__(self, model=None, temperature=1.0):
        self.model = (model or "unknown").lower()
        self.temperature = temperature

        # All connection settings come from the .env file
        api_key  = _get_env("ARIADNE_API_KEY")
        base_url = _get_env("ARIADNE_BASE_URL").rstrip("/")
        model_id = _get_env("ARIADNE_MODEL_ID")
        provider = _get_env("ARIADNE_PROVIDER")

        missing = [k for k, v in {
            "ARIADNE_API_KEY":   api_key,
            "ARIADNE_BASE_URL":  base_url,
            "ARIADNE_MODEL_ID":  model_id,
            "ARIADNE_PROVIDER":  provider,
        }.items() if not v]
        if missing:
            raise ValueError(
                f"Missing required environment variable(s): {', '.join(missing)}"
            )

        self._ariadne_model    = model_id
        self._ariadne_provider = provider
        self._base_url         = base_url

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

    def send_message(self, messages):
        """Format messages and send them to the Ariadne /messages endpoint."""
        start_time = time.time()

        # Get input text for tracking
        input_text = _extract_input_text(messages)

        # Format and call the API
        formatted_messages = self._format_messages(messages)
        response = self._ariadne_api(formatted_messages)

        # Track the request
        request_time = time.time() - start_time
        _track_request(self.model, input_text, response, request_time)

        return response

    # ------------------------------------------------------------------
    # Message formatting
    # ------------------------------------------------------------------

    def _format_messages(self, messages):
        """
        Convert internal message list (dicts with 'role'/'message' keys)
        to the Ariadne /messages format (role + content string).
        """
        formatted = []
        for m in messages:
            formatted.append({
                "role": m["role"],
                "content": m["message"],
            })
        return formatted

    # ------------------------------------------------------------------
    # API call
    # ------------------------------------------------------------------

    def _ariadne_api(self, formatted_messages):
        """
        POST to the Ariadne /api/v1/messages endpoint and return the
        text content of the first response block.
        """
        payload = {
            "messages":    formatted_messages,
            "provider":    self._ariadne_provider,
            "model":       self._ariadne_model,
            "temperature": self.temperature,
            "max_tokens":  16384,
        }

        url = f"{self._base_url}/messages"
        resp = self._session.post(url, json=payload, timeout=120)
        if resp.status_code == 402:
            raise InsufficientCreditsError(
                "API returned 402 Payment Required — account credits exhausted. "
                "Recharge credits and re-run the same command; the pipeline will "
                "resume automatically from the last checkpoint."
            )
        resp.raise_for_status()

        data = resp.json()
        # Response schema: {"content": [{"type": "text", "text": "..."}], ...}
        content_blocks = data.get("content", [])
        return "".join(block.get("text", "") for block in content_blocks)


# Tracking utility functions
def set_current_project(project_name):
    """Set the current project for tracking purposes"""
    global _current_project
    _current_project = project_name

def get_llm_stats(project_name=None):
    """Get LLM statistics (global or for specific project)"""
    global _global_stats, _project_stats

    if project_name:
        if project_name not in _project_stats:
            return {'error': f'No stats found for project: {project_name}'}

        stats = _project_stats[project_name]
        avg_request_time = stats['total_request_time'] / stats['request_count'] if stats['request_count'] > 0 else 0
        total_tokens = stats['total_input_tokens'] + stats['total_output_tokens']

        return {
            'project_name': project_name,
            'request_count': stats['request_count'],
            'total_request_time': stats['total_request_time'],
            'average_request_time': avg_request_time,
            'total_input_tokens': stats['total_input_tokens'],
            'total_output_tokens': stats['total_output_tokens'],
            'total_tokens': total_tokens,
            'request_history': stats['request_history']
        }
    else:
        avg_request_time = _global_stats['total_request_time'] / _global_stats['request_count'] if _global_stats['request_count'] > 0 else 0
        total_tokens = _global_stats['total_input_tokens'] + _global_stats['total_output_tokens']

        return {
            'request_count': _global_stats['request_count'],
            'total_request_time': _global_stats['total_request_time'],
            'average_request_time': avg_request_time,
            'total_input_tokens': _global_stats['total_input_tokens'],
            'total_output_tokens': _global_stats['total_output_tokens'],
            'total_tokens': total_tokens,
            'request_history': _global_stats['request_history']
        }

def get_all_project_stats():
    """Get statistics for all projects"""
    global _project_stats
    all_stats = {}
    for project_name in _project_stats.keys():
        all_stats[project_name] = get_llm_stats(project_name)
    return all_stats

def reset_llm_stats(project_name=None):
    """Reset LLM statistics (global or for specific project)"""
    global _global_stats, _project_stats

    if project_name:
        if project_name in _project_stats:
            _project_stats[project_name] = {
                'request_count': 0,
                'total_request_time': 0.0,
                'total_input_tokens': 0,
                'total_output_tokens': 0,
                'request_history': []
            }
    else:
        _global_stats = {
            'request_count': 0,
            'total_request_time': 0.0,
            'total_input_tokens': 0,
            'total_output_tokens': 0,
            'request_history': []
        }
        _project_stats.clear()


def _get_env(key):
    """Read an env var and strip surrounding whitespace and accidental quotes."""
    val = os.environ.get(key, "")
    return val.strip().strip('"').strip("'")


def check_connection():
    """
    Verify the Ariadne API is reachable and the token is valid by:
      1. Fetching /api/v1/models to get the list of available models.
      2. Using the first returned model to send a "Hello!" chat message
         via /api/v1/chat.

    Returns:
        dict: {'ok': True,  'response': <model reply>, 'model': <model id>,
                             'provider': <provider>, 'elapsed': <seconds>}
              {'ok': False, 'error': <message>, 'elapsed': <seconds>}
    """
    api_key  = _get_env("ARIADNE_API_KEY")
    base_url = _get_env("ARIADNE_BASE_URL").rstrip("/")

    missing = [k for k, v in {
        "ARIADNE_API_KEY":  api_key,
        "ARIADNE_BASE_URL": base_url,
    }.items() if not v]
    if missing:
        return {
            'ok': False,
            'error': f"Missing environment variable(s): {', '.join(missing)}",
            'elapsed': 0.0,
        }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }

    start = time.time()
    try:
        # Step 1 — get available models
        models_url = f"{base_url}/models"
        resp = requests.get(models_url, headers=headers, timeout=15)
        resp.raise_for_status()
        models = resp.json().get("data", [])
        if not models:
            return {
                'ok': False,
                'error': "No models returned by /v1/models",
                'elapsed': round(time.time() - start, 2),
            }

        first_model = models[0]
        provider    = first_model["provider"]
        model_id    = first_model["id"]

        # Step 2 — send a single chat message using the first available model
        chat_url  = f"{base_url}/chat"
        chat_resp = requests.post(
            chat_url,
            headers=headers,
            json={
                "provider": provider,
                "model":    model_id,
                "message":  "Hello!",
            },
            timeout=15,
        )
        chat_resp.raise_for_status()
        data  = chat_resp.json()
        reply = "".join(
            block.get("text", "") for block in data.get("content", [])
        )
        return {
            'ok':       True,
            'response': reply.strip(),
            'model':    model_id,
            'provider': provider,
            'elapsed':  round(time.time() - start, 2),
        }
    except requests.exceptions.ConnectionError as e:
        return {'ok': False, 'error': f"Connection error: {e}",                                    'elapsed': round(time.time() - start, 2)}
    except requests.exceptions.Timeout:
        return {'ok': False, 'error': "Request timed out after 15 s",                              'elapsed': round(time.time() - start, 2)}
    except requests.exceptions.HTTPError as e:
        return {'ok': False, 'error': f"HTTP {e.response.status_code}: {e.response.text}",         'elapsed': round(time.time() - start, 2)}
    except Exception as e:
        return {'ok': False, 'error': str(e),                                                      'elapsed': round(time.time() - start, 2)}


if __name__ == "__main__":
    import sys

    api_key  = _get_env("ARIADNE_API_KEY")
    base_url = _get_env("ARIADNE_BASE_URL").rstrip("/")

    # ── env diagnostics ────────────────────────────────────────────────
    print("=" * 60)
    print("ARIADNE API — connection debug")
    print("=" * 60)
    print(f"  .env file loaded from : {os.path.abspath('.env')}")
    print(f"  ARIADNE_BASE_URL (raw): {os.environ.get('ARIADNE_BASE_URL', '(not set)')!r}")
    print(f"  ARIADNE_BASE_URL (use): {base_url!r}")
    print(f"  ARIADNE_API_KEY  (raw): {os.environ.get('ARIADNE_API_KEY', '(not set)')!r}")
    if api_key:
        masked = api_key[:12] + "*" * max(0, len(api_key) - 12)
        print(f"  ARIADNE_API_KEY  (use): {masked!r}  (len={len(api_key)})")
    else:
        print("  ARIADNE_API_KEY  (use): (EMPTY — check .env)")
    print()

    # ── step 1: GET /v1/models ─────────────────────────────────────────
    models_url = f"{base_url}/models"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }
    print(f"[1] GET {models_url}")
    print(f"    Authorization header: Bearer {api_key[:12]}{'*' * max(0, len(api_key)-12)}")
    try:
        resp = requests.get(models_url, headers=headers, timeout=15)
        print(f"    Status : {resp.status_code}")
        print(f"    Body   : {resp.text[:500]}")
        resp.raise_for_status()
        models = resp.json().get("data", [])
        print(f"    Models : {[m['id'] for m in models]}")
    except requests.exceptions.HTTPError:
        print("\n  FAILED at step 1 — fix the error above and retry.")
        sys.exit(1)
    except Exception as e:
        print(f"\n  FAILED at step 1 — {e}")
        sys.exit(1)

    if not models:
        print("\n  No models returned. Cannot proceed.")
        sys.exit(1)

    first_model = models[0]
    provider    = first_model["provider"]
    model_id    = first_model["id"]
    print()

    # ── step 2: POST /v1/chat ──────────────────────────────────────────
    chat_url = f"{base_url}/chat"
    payload  = {"provider": provider, "model": model_id, "message": "Hello!"}
    print(f"[2] POST {chat_url}")
    print(f"    Payload: {payload}")
    try:
        chat_resp = requests.post(chat_url, headers=headers, json=payload, timeout=15)
        print(f"    Status : {chat_resp.status_code}")
        print(f"    Body   : {chat_resp.text[:500]}")
        chat_resp.raise_for_status()
        data  = chat_resp.json()
        reply = "".join(block.get("text", "") for block in data.get("content", []))
        print(f"\n  SUCCESS — model replied: {reply.strip()!r}")
    except requests.exceptions.HTTPError:
        print("\n  FAILED at step 2 — fix the error above and retry.")
        sys.exit(1)
    except Exception as e:
        print(f"\n  FAILED at step 2 — {e}")
        sys.exit(1)

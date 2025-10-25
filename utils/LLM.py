import os
import json
import time
import requests
from dotenv import load_dotenv
from collections import defaultdict

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
        texts = []
        for m in messages:
            if isinstance(m, dict):
                text = m.get("content", "") or m.get("message", "")
                texts.append(text)
        return " ".join(texts)
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
    def __init__(self, model, temperature=1.0, access_token=None):
        self.api_url = "https://services.issel.ee.auth.gr/llms/claude"
        self.access_token = access_token or os.environ.get("CLAUDE_ACCESS_TOKEN")
        self.temperature = temperature
        self.model = model # unused kept for compatibility with the previous handler

        if not self.access_token:
            raise ValueError("Access token is required. Set CLAUDE_ACCESS_TOKEN environment variable or pass it to constructor.")
        
        self.headers = {
            "access_token": self.access_token,
            "Content-Type": "application/json"
        }
    
    def send_message(self, messages, max_retries=3, timeout=120):
        """Send messages to Claude API with retries and exponential backoff."""
        start_time = time.time()

        # Format messages and prepare payload
        formatted_messages = self._format_messages(messages)
        input_text = _extract_input_text(formatted_messages)
        payload = {"messages": formatted_messages, "temperature": self.temperature}

        backoff = 1.0
        for attempt in range(1, max_retries + 1):
            try:
                resp = requests.post(self.api_url, headers=self.headers, json=payload, timeout=timeout)
            except requests.exceptions.RequestException as e:
                # network-level failure: retry if attempts remain
                if attempt < max_retries:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                raise Exception(f"API request failed: {e}")

            # Retry on server-side 5xx errors
            if 500 <= resp.status_code < 600:
                snippet = resp.text[:2000]
                if attempt < max_retries:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                raise Exception(f"Server error {resp.status_code}: {snippet}")

            # Raise for other HTTP errors and include response body for debugging
            try:
                resp.raise_for_status()
            except requests.exceptions.HTTPError:
                snippet = resp.text[:2000]
                raise Exception(f"HTTP error {resp.status_code}: {snippet}")

            # Parse response (JSON preferred, fallback to raw text)
            try:
                response_data = resp.json()
                output_text = self._extract_response_content(response_data)
            except (ValueError, json.JSONDecodeError):
                output_text = resp.text

            # Track timing and tokens
            end_time = time.time()
            request_time = end_time - start_time
            _track_request(self.model or "claude", input_text, output_text, request_time)

            return output_text

        # If loop finishes without returning, raise generic error
        raise Exception("Failed to receive a successful response after retries")
    
    def _format_messages(self, messages):
        """Format messages for the Claude API"""
        formatted_messages = []
        
        for message in messages:
            if isinstance(message, dict):
                # If message has 'message' key (old format), convert it
                if "message" in message:
                    formatted_messages.append({
                        "role": message.get("role", "user"),
                        "content": message["message"]
                    })
                # If message already has 'content' key (new format), use as is
                elif "content" in message:
                    formatted_messages.append({
                        "role": message.get("role", "user"),
                        "content": message["content"]
                    })
                else:
                    # Fallback: treat the whole dict as content
                    formatted_messages.append({
                        "role": "user",
                        "content": str(message)
                    })
            else:
                # If message is a string, wrap it in user role
                formatted_messages.append({
                    "role": "user",
                    "content": str(message)
                })
        
        return formatted_messages
    
    def _extract_response_content(self, response_data):
        """Extract content from API response"""
        # Handle different possible response formats
        if isinstance(response_data, dict):
            # Check for common response formats
            if "content" in response_data:
                return response_data["content"]
            elif "message" in response_data:
                return response_data["message"]
            elif "text" in response_data:
                return response_data["text"]
            elif "response" in response_data:
                return response_data["response"]
            else:
                # Return the whole response as string if no known format
                return str(response_data)
        else:
            return str(response_data)

# Tracking utility functions (same as original LLM.py)
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
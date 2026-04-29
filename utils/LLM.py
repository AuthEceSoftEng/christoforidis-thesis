"""
Multi-model LLM handler for interacting with different language model providers.

Supports three backends:
  - Claude 3.7 Sonnet (via AWS Bedrock) - primary model
  - Llama 3.2 (via AWS Bedrock)
  - GPT-4o (via OpenAI API, currently disabled)

Provides a unified `LLMHandler` class that abstracts away model-specific
message formatting and API calls. Also includes global and per-project
statistics tracking (request count, timing, token estimation) for
performance analysis during evaluation runs.

Environment Variables:
    ACCOUNT_ID: AWS account ID for constructing Bedrock inference profile ARNs.
    OPENAI_API_KEY: (Optional) OpenAI API key for GPT-4o support.
"""

import os
import json
import boto3 # type: ignore
import time
from openai import OpenAI # type: ignore
from dotenv import load_dotenv # type: ignore
from botocore.config import Config
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
    def __init__(self, model, temperature=1.0):
        self.model = model.lower()
        self.temperature = temperature
        
        self.model_apis = {
            'gpt': self._gpt_api,
            'llama': self._llama_api,
            'claude': self._claude_api
        }
        
        if self.model not in self.model_apis:
            raise ValueError("Unsupported model. Choose from 'gpt', 'llama', or 'claude'.")

        # self.gpt_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        ACCOUNT_ID = os.environ.get("ACCOUNT_ID")
        if not ACCOUNT_ID:
            raise ValueError("ACCOUNT_ID environment variable is not set.")
        
        timeout_config = Config(
            connect_timeout=10,
            read_timeout=120
        )

        self.llama_session = boto3.Session()
        self.llama_client = self.llama_session.client(service_name="bedrock-runtime", region_name="eu-central-1")
        self.llama_model_id = f"arn:aws:bedrock:eu-central-1:{ACCOUNT_ID}:inference-profile/eu.meta.llama3-2-3b-instruct-v1:0"
        
        self.claude_session = boto3.Session()
        self.claude_client = self.claude_session.client(service_name="bedrock-runtime", region_name="eu-central-1", config=timeout_config)
        self.claude_model_id = f"arn:aws:bedrock:eu-central-1:{ACCOUNT_ID}:inference-profile/eu.anthropic.claude-3-7-sonnet-20250219-v1:0"
        #self.claude_model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
    
    def send_message(self, messages):
        # Add tracking wrapper around existing method
        start_time = time.time()
        
        # Get input text for tracking
        input_text = _extract_input_text(messages)
        
        # Call original method
        formatted_messages = self._format_messages(messages)
        response = self.model_apis[self.model](formatted_messages)
        
        # Track the request
        end_time = time.time()
        request_time = end_time - start_time
        _track_request(self.model, input_text, response, request_time)
        
        return response
    
    def _format_messages(self, messages):
        if self.model == 'gpt':
            return self._format_for_gpt(messages)
        elif self.model == 'llama':
            return self._format_for_llama(messages)
        elif self.model == 'claude':
            return self._format_for_claude(messages)
    
    def _format_for_gpt(self, messages):
        formatted_messages = []
        for m in messages:
            formatted_messages.append({
                "role": m["role"],
                "content": m["message"]
            })
        return formatted_messages
    
    def _format_for_llama(self, messages):
        prompt = f"""
        <|begin_of_text|>
        """
        for m in messages:
            prompt += f"""
            <|start_header_id|>{m["role"]}<|end_header_id|>
            {m["message"]}
            <|eot_id|>
            """
        prompt += """
        <|start_header_id|>assistant<|end_header_id|>
        """
        return prompt
    
    def _format_for_claude(self, messages):
        formatted_messages = []
        for m in messages:
            formatted_messages.append({
                "role": m["role"],
                "content": [{"type": "text", "text": m["message"]}]
            })
        return formatted_messages
    
    def _gpt_api(self, formatted_messages):
        response = self.gpt_client.chat.completions.create(
            model="gpt-4o",
            messages=formatted_messages,
            temperature=self.temperature,
        )
        return response.choices[0].message.content
    
    def _llama_api(self, formatted_messages):
        response = self.llama_client.invoke_model(
            body=json.dumps({"prompt": formatted_messages}),
            modelId=self.llama_model_id
        )

        model_response = json.loads(response["body"].read())
        response_text = model_response["generation"]
        return response_text
    
    def _claude_api(self, formatted_messages):
        response = self.claude_client.invoke_model(
                modelId=self.claude_model_id,
                body=json.dumps(
                    {
                        "anthropic_version": "bedrock-2023-05-31",
                        "max_tokens": 4096,
                        "messages": formatted_messages,
                        "temperature": self.temperature,
                    }
                ),
            )
        result = json.loads(response.get("body").read())
        output_list = result.get("content", [])
        response = ""
        for output in output_list:
            response += output["text"]
        return response

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
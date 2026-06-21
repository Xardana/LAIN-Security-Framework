"""
ai_client.py
============
Single responsibility: talk to the local LLM (Large Language Model) API and
hand back a structured result. It does NOT build prompts, validate scripts, or
write reports - those jobs live in other modules.

Where this fits in the program:
    prompt_builder.py  ->  ai_client.py  ->  validator.py
    (writes the text)      (this file)       (checks the reply)

Coding requirements demonstrated in THIS file:
    * Functions - every behaviour below is written as a def.
    * Modules   - uses the standard-library `os` module to read configuration
                  from environment variables (so secrets are never hard-coded).
"""

import json            # standard library: turn the model's text reply into a dict
import os              # [REQUIREMENT: Module os] read settings from the environment
import re              # standard library: pull a JSON/code block out of messy text

from dotenv import load_dotenv   # third-party: load values from a local .env file
from openai import OpenAI        # third-party: OpenAI-compatible client (works with local Ollama)

# Read AI_API_BASE_URL / AI_API_KEY / AI_MODEL from a local .env file (if one
# exists) into os.environ, so the local LLM's address and key stay out of source.
load_dotenv()

# Fallback model name, used only when AI_MODEL is not set in the environment.
DEFAULT_MODEL = "huihui_ai/foundation-sec-abliterated"

# Module-level cache: build the API client once, then reuse it on later calls.
_client = None


def _get_client():
    """Build (once) and return the OpenAI-compatible client.

    The connection details are read from environment variables through the `os`
    module, so the local LLM's IP and key never appear in this file. The created
    client is stored in the module-level `_client` variable so we only build it
    a single time.
    """
    global _client
    if _client is None:
        # [REQUIREMENT: Module os] AI_API_BASE_URL must be provided (e.g. via .env).
        base_url = os.environ["AI_API_BASE_URL"]
        # Local Ollama-served models ignore the key, but the OpenAI client still
        # demands a non-empty string, so we default it to "ollama".
        api_key = os.environ.get("AI_API_KEY", "ollama")
        _client = OpenAI(base_url=base_url, api_key=api_key)
    return _client


def send(system_prompt, user_prompt, model=None):
    """Send the system + user prompt to the local LLM and return parsed JSON.

    The two inputs are strings (the safety rules and the actual request). The
    return value is a dict such as {"script": "...", "explanation": "..."} that
    the validator can inspect. This is the only function other modules call.
    """
    client = _get_client()
    # Pick the caller's model if given, else the environment, else the default.
    model = model or os.environ.get("AI_MODEL", DEFAULT_MODEL)

    # One chat-completion request: the "system" message carries the safety rules
    # and the "user" message carries the audit task we want a script for.
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )

    # The model's text reply is nested inside the response object.
    content = response.choices[0].message.content
    return _parse_response(content)


def _parse_response(content):
    """Turn the model's raw text reply into a Python dict.

    Small models don't always return clean JSON, so we try three things in order:
      1) parse the entire reply as JSON;
      2) find a ```json { ... } ``` fenced block and parse that;
      3) give up on JSON and treat a ```python ...``` block (or the whole text)
         as the script, wrapped in the dict shape the rest of the program expects.
    """
    # Attempt 1: the whole reply is already valid JSON.
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Attempt 2: a fenced ```json { ... } ``` block somewhere inside the text.
    json_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if json_block:
        try:
            return json.loads(json_block.group(1))
        except json.JSONDecodeError:
            pass

    # Attempt 3: fall back to treating a code block (or the raw text) as the script.
    code_block = re.search(r"```(?:python)?\s*(.*?)```", content, re.DOTALL)
    script = code_block.group(1).strip() if code_block else content.strip()

    return {"script": script, "raw_response": content}

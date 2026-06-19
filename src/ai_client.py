"""Handles all communication with the local LLM API. No system info collection,
validation, or report writing belongs here.
"""

import json
import os
import re

from openai import OpenAI

DEFAULT_BASE_URL = "http://192.168.1.103:11434/v1"
DEFAULT_MODEL = "huihui_ai/foundation-sec-abliterated"

_client = None


def _get_client():
    global _client
    if _client is None:
        base_url = os.environ.get("AI_API_BASE_URL", DEFAULT_BASE_URL)
        # Local Ollama-served models don't check the key, but the OpenAI
        # client requires a non-empty string.
        api_key = os.environ.get("AI_API_KEY", "ollama")
        _client = OpenAI(base_url=base_url, api_key=api_key)
    return _client


def send(system_prompt, user_prompt, model=None):
    """Send the system/user prompt pair to the local LLM and return the
    generated script data as structured JSON, e.g. {"script": "...", ...}.
    """
    client = _get_client()
    model = model or os.environ.get("AI_MODEL", DEFAULT_MODEL)

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )

    content = response.choices[0].message.content
    return _parse_response(content)


def _parse_response(content):
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    json_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if json_block:
        try:
            return json.loads(json_block.group(1))
        except json.JSONDecodeError:
            pass

    code_block = re.search(r"```(?:python)?\s*(.*?)```", content, re.DOTALL)
    script = code_block.group(1).strip() if code_block else content.strip()

    return {"script": script, "raw_response": content}

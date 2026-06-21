# ai_client.py - the only module that actually talks to the local LLM.
# (prompt_builder builds the text to send; validator checks the reply.)

import json            # json.loads() converts a JSON-formatted string into a Python dict
import os              # [REQUIREMENT: Module os] os.environ reads config from the environment
import re              # re.search() finds text patterns (used to dig JSON out of the reply)

from dotenv import load_dotenv   # helper that loads a local ".env" file into the environment
from openai import OpenAI        # the client class that speaks the OpenAI-style API

# Runs once at import time: copies KEY=VALUE lines from a local .env file into
# os.environ, so the LLM's address/key live in .env instead of in this source file.
load_dotenv()

# A constant (UPPER_CASE by convention): the model name used only if AI_MODEL is unset.
DEFAULT_MODEL = "huihui_ai/foundation-sec-abliterated"

# Module-level variable, starts empty. We build the client the first time it is
# needed and store it here so later calls reuse the same object instead of rebuilding.
_client = None        # the leading "_" is a convention meaning "internal to this module"


def _get_client():
    # Build (once) and return the API client object.
    global _client                       # without this, assigning below would create a
                                          # new LOCAL variable instead of updating the module one
    if _client is None:                  # True only on the very first call
        # os.environ["NAME"] reads a REQUIRED variable; it raises KeyError if the
        # variable is missing - which we want (better to fail loudly than connect to nothing).
        base_url = os.environ["AI_API_BASE_URL"]      # e.g. http://192.168.1.103:11434/v1
        # os.environ.get("NAME", default) reads an OPTIONAL variable, returning the
        # default when it is not set. Local Ollama models ignore the key, but the
        # OpenAI client still requires some non-empty string.
        api_key = os.environ.get("AI_API_KEY", "ollama")
        # Create the client object with those two settings and cache it in _client.
        _client = OpenAI(base_url=base_url, api_key=api_key)
    return _client                       # hand back the cached client


def send(system_prompt, user_prompt, model=None):
    # Public function: send the two prompt strings to the LLM and return parsed JSON.
    client = _get_client()               # get (or build) the shared client
    # "a or b" returns a if it is truthy, otherwise b. So: use the model the caller
    # passed in; if they passed None, fall back to the env var; if that's unset, the default.
    model = model or os.environ.get("AI_MODEL", DEFAULT_MODEL)

    # Ask the model for one chat completion. "messages" is a list of dicts:
    # the "system" message carries the rules, the "user" message carries the request.
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )

    # The reply text is nested deep in the response object: the first choice's
    # message's content. [0] is the first item of the choices list.
    content = response.choices[0].message.content
    return _parse_response(content)      # hand the raw text to the parser below


def _parse_response(content):
    # Turn the model's raw text into a Python dict. Small models don't always
    # return clean JSON, so we try three strategies in order.

    # Strategy 1: assume the whole reply is already valid JSON.
    try:
        return json.loads(content)       # success -> return the dict immediately
    except json.JSONDecodeError:         # raised when the text is not valid JSON
        pass                             # "pass" = do nothing, fall through to strategy 2

    # Strategy 2: look for a ```json { ... } ``` block somewhere in the text.
    # The regex: ``` then optional "json", then capture (...) the {...} object.
    # re.DOTALL makes "." also match newlines so the object can span lines.
    json_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if json_block:                       # truthy only if a match was found
        try:
            return json.loads(json_block.group(1))   # group(1) = the captured {...} text
        except json.JSONDecodeError:
            pass                         # captured text wasn't valid JSON either

    # Strategy 3: give up on JSON. Treat a ```python ...``` code block as the script.
    code_block = re.search(r"```(?:python)?\s*(.*?)```", content, re.DOTALL)
    # Ternary "X if cond else Y": if we found a code block use its inner text
    # (stripped of surrounding whitespace), otherwise use the whole reply stripped.
    script = code_block.group(1).strip() if code_block else content.strip()

    # Wrap whatever we salvaged in the same dict shape the rest of the program expects,
    # and keep the original text under "raw_response" for the report/debugging.
    return {"script": script, "raw_response": content}

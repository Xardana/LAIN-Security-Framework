# ai_client.py - the ONLY module that talks to the local LLM over HTTP.
# Architectural role: we deliberately isolate all network/API code here so the
# rest of the program depends on a single function, send(). If the AI backend
# ever changes, only this file changes. (This is the "single responsibility
# principle" - each module owns one job.)

import json            # stdlib JSON codec. json.loads() = "load string" (text -> Python objects);
                       # json.dumps() = "dump string" (objects -> text). Used here to parse replies.
import os              # [REQUIREMENT: Module os] gives access to the operating system, including
                       # os.environ, the process's environment variables.
import re              # stdlib "regular expressions" engine - pattern matching inside strings.

from dotenv import load_dotenv   # third-party helper: reads a ".env" file from disk.
from openai import OpenAI        # third-party SDK class; an instance speaks the OpenAI HTTP API.

# load_dotenv() runs IMMEDIATELY when this module is first imported (top-level code
# executes at import time). UNDER THE HOOD it opens a local ".env" file, parses each
# KEY=VALUE line, and inserts those pairs into os.environ. WHY: it keeps secrets (the
# LLM's IP, API key) out of the source code and out of git - they live only in .env.
load_dotenv()

# A module-level constant. UPPER_CASE is the Python convention signalling "do not
# reassign this." It is the fallback model name if no AI_MODEL is configured.
DEFAULT_MODEL = "huihui_ai/foundation-sec-abliterated"

# Module-level cache, starting empty (None). WHY: building the OpenAI client sets up
# configuration we don't want to repeat on every request, so we create it once and
# remember it here. The leading "_" is a naming convention meaning "private/internal."
_client = None


def _get_client():
    # WHY (logic): lazy initialization - build the client the first time it's needed,
    # then reuse it. This is a common performance pattern (a lightweight singleton).
    # HOW (syntax): the `global` keyword is required because, by default, ASSIGNING to
    # a name inside a function creates a NEW local variable. `global _client` tells
    # Python "the _client I assign to is the module-level one," so the cache persists.
    global _client
    if _client is None:                  # `is None` checks identity (the one None object); runs once
        # os.environ behaves like a dict. Subscripting it with ["KEY"] looks the value up
        # and RAISES KeyError if the key is missing. WHY we want that here: if there's no
        # base URL we cannot connect, so failing loudly is better than connecting to nothing.
        base_url = os.environ["AI_API_BASE_URL"]      # [REQUIREMENT: Module os]
        # dict.get("KEY", default) is the SAFE lookup: it returns the value if present,
        # otherwise the default ("ollama"), and never raises. WHY: local Ollama models
        # ignore the key, but the OpenAI client still requires a non-empty string.
        api_key = os.environ.get("AI_API_KEY", "ollama")
        # Construct the SDK client object (calls OpenAI.__init__ under the hood) and store
        # it in the cache. base_url points the SDK at our LOCAL server instead of openai.com.
        _client = OpenAI(base_url=base_url, api_key=api_key)
    return _client                       # hand back the cached instance


def send(system_prompt, user_prompt, model=None):
    # WHY (logic): this is the module's single public entry point. It hides the entire
    # request/response/parse dance behind two string inputs and a dict output, so callers
    # never touch the network directly.
    client = _get_client()               # get (or lazily build) the shared client
    # HOW (syntax): `a or b` is short-circuit evaluation - it returns `a` if `a` is
    # "truthy" (here: a real model name was passed), otherwise it evaluates and returns `b`.
    # So this reads: caller's model, else the AI_MODEL env var, else the hard-coded default.
    model = model or os.environ.get("AI_MODEL", DEFAULT_MODEL)

    # client.chat.completions.create(...) is the SDK call that UNDER THE HOOD serialises
    # these arguments to JSON, sends an HTTP POST to the chat-completions endpoint, waits
    # for the reply, and returns a response object. `messages` is a list of dicts - the
    # standard chat format where each message has a "role" (system/user/assistant) and
    # "content". WHY two messages: the "system" message sets the rules/identity, the
    # "user" message carries the actual task; the model weighs the system message heavily.
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )

    # The SDK returns a structured object. We navigate it: .choices is a LIST of candidate
    # replies; [0] takes the first; .message is that reply's message object; .content is the
    # actual text string. WHY index [0]: we asked for one completion, so we want the first.
    content = response.choices[0].message.content
    return _parse_response(content)      # delegate the messy text->dict parsing below


def _parse_response(content):
    # WHY (logic): small local LLMs frequently wrap their JSON in prose or code fences
    # instead of returning clean JSON. Rather than trust them, we try three increasingly
    # forgiving strategies. This "defensive parsing" keeps the pipeline robust.

    # --- Strategy 1: assume the whole reply is valid JSON. ---
    # try/except is Python's error handling: the code in `try` runs; if it raises the
    # specific error named in `except`, control jumps there instead of crashing.
    try:
        # json.loads() parses a JSON string into Python objects (a dict here). It RAISES
        # json.JSONDecodeError (a subclass of ValueError) if the text isn't valid JSON.
        return json.loads(content)
    except json.JSONDecodeError:
        pass                             # `pass` = "do nothing"; we fall through to Strategy 2

    # --- Strategy 2: find a fenced ```json { ... } ``` block inside the text. ---
    # re.search(pattern, string, flags) scans the WHOLE string for the FIRST place the
    # pattern matches and returns a Match object, or None if there's no match.
    # The r"..." is a RAW string so backslashes are literal (regex needs them).
    # Pattern parts: ``` then optional "json"; \s* = any whitespace; (\{.*?\}) is a
    # CAPTURE GROUP grabbing a {...} block; .*? is "non-greedy" (smallest match).
    # re.DOTALL makes "." also match newlines so the JSON can span multiple lines.
    json_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if json_block:                       # a Match object is truthy; None is falsy
        try:
            # .group(1) returns the text captured by the FIRST (...) group - just the {...}.
            return json.loads(json_block.group(1))
        except json.JSONDecodeError:
            pass

    # --- Strategy 3: give up on JSON; treat a code block (or the whole reply) as the script. ---
    code_block = re.search(r"```(?:python)?\s*(.*?)```", content, re.DOTALL)
    # Ternary expression "VALUE_IF_TRUE if CONDITION else VALUE_IF_FALSE":
    # if we found a code block, use its inner text; otherwise use the entire reply.
    # .strip() returns a new string with leading/trailing whitespace removed.
    script = code_block.group(1).strip() if code_block else content.strip()

    # Return a dict in the SAME shape callers expect ({"script": ...}), keeping the raw
    # text under "raw_response" so nothing is lost for the report/debugging.
    return {"script": script, "raw_response": content}

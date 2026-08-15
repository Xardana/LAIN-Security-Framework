"""
This is the only file that talks to the AI. It sends a question, gets an answer
back, and tidies it up. Everything about the AI lives here, so if we ever swap in
a different provider, this is the only file we touch.
"""

import json
import os
import re

from dotenv import load_dotenv        # reads our settings out of the .env file
from openai import OpenAI             # the library we use to talk to the AI
from openai import BadRequestError    # the error the server throws when it doesn't like our request


# Load the .env file first, so the settings are ready before anything else runs.
load_dotenv()


DEFAULT_MODEL = "huihui_ai/foundation-sec-abliterated"

# How long to wait for the AI before giving up, in seconds. A local model writing a
# whole script is slow, so we're generous, but we still need a limit or a stuck
# server would hang us forever.
REQUEST_TIMEOUT = 180

# How much freedom the AI gets, 0 to 1. We keep it low. We want a script in a strict
# format, not creative writing, so the more predictable the answer the better.
TEMPERATURE = 0.2

# We build the connection to the AI once and keep it here to reuse.
_client = None


def _get_client():
    """Build the connection the first time we're asked, then reuse it forever after.
    That's all `global` is doing here, keeping the connection around instead of
    throwing it away when the function ends."""
    global _client
    if _client is None:                  # only build it if we haven't already
        # We need the address of the AI server. If it's missing we stop right now
        # with an error, rather than quietly trying to connect to nothing.
        base_url = os.environ["AI_API_BASE_URL"]      # [REQUIREMENT: Module os]
        # Some servers need a secret key, ours doesn't. Read it if it's there, and if
        # not, use a throwaway word so we don't fall over.
        api_key = os.environ.get("AI_API_KEY", "ollama")
        # Make the connection and stash it for next time.
        _client = OpenAI(base_url=base_url, api_key=api_key, timeout=REQUEST_TIMEOUT)
    return _client                       # hand back the saved connection


def _ask(client, model, messages, force_json):
    """Send the question. `force_json` tells the server its reply must be valid JSON,
    which saves us a lot of cleanup later. Not every server supports that, so the
    caller below is ready for it to fail."""
    settings = {"model": model, "messages": messages, "temperature": TEMPERATURE}
    if force_json:
        settings["response_format"] = {"type": "json_object"}
    return client.chat.completions.create(**settings)


def send(system_prompt, user_prompt, model=None):
    """The one function the rest of the program uses to talk to the AI. Hand it two
    bits of text and it does the rest: connect, ask, and turn the answer into
    something usable."""
    client = _get_client()               # reuse the saved connection, or build it
    # Pick the model: the one we were told to use, else the one in settings, else our default.
    model = model or os.environ.get("AI_MODEL", DEFAULT_MODEL)

    # Two messages: the "system" one tells the AI how to behave, the "user" one is the
    # actual question.
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        # First choice: make the server hand us valid JSON.
        response = _ask(client, model, messages, force_json=True)
    except BadRequestError:
        # The server said no, which nearly always means this version doesn't support
        # the force-JSON option. No reason to fail the whole run over a nice-to-have,
        # so we just ask again the plain way and clean up the reply ourselves below.
        # We only catch this one error on purpose. A timeout or a dropped connection
        # should still blow up loudly, not get quietly retried.
        response = _ask(client, model, messages, force_json=False)

    # The reply comes wrapped in a few layers. Dig out the plain text.
    content = response.choices[0].message.content
    return _parse_response(content)      # turn that text into something usable


def _as_dict(text):
    """Try to read text as a JSON object. Give back the object if it worked, or None
    if it didn't, so the caller can just try the next thing.

    We insist on an object specifically. Valid JSON can also be a plain string or a
    list, and those would slip through json.loads and then break everything later
    that expects to look up "script" on the result."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None                      # not JSON at all
    return data if isinstance(data, dict) else None


def _parse_response(content):
    """Small models don't always answer cleanly. Sometimes they wrap the answer in
    extra chatter or formatting. So we try a few ways of reading it, from strictest
    to most forgiving, until one sticks."""

    # The model can hand back nothing at all, an empty reply or no text. That used to
    # crash the program with a confusing JSON error, so we catch it and return an
    # empty script. The validator then rejects it with a clear "nothing to run" and
    # the normal retry takes over.
    if not content:
        return {"script": "", "explanation": "", "raw_response": ""}

    # Best case: the whole reply is already the clean JSON we wanted.
    data = _as_dict(content)
    if data is not None:
        return _normalize(data, content)

    # Next try: the model tucked the JSON inside a fenced code block. Pull out the part
    # between the fences and read that.
    json_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if json_block:                       # found something fenced?
        data = _as_dict(json_block.group(1))
        if data is not None:
            return _normalize(data, content)

    # Last resort: give up on clean JSON and just treat the whole reply as the script.
    code_block = re.search(r"```(?:python)?\s*(.*?)```", content, re.DOTALL)
    script = code_block.group(1).strip() if code_block else content.strip()

    # Hand it back in the usual shape, keeping the raw text too in case we want it
    # later for the report or for digging into a problem.
    return {"script": script, "explanation": "", "raw_response": content}


def _strip_code_fence(text):
    """Peel the markdown wrapper off a script if the model added one.

    Models love to present code in "fences", three backticks with a language name
    like ```python, because that's how code looks on a web page. Trouble is they do
    it inside the JSON too, so the script comes back reading "```python3\\nimport
    os..." instead of starting at the real code. That's perfectly good JSON and
    completely broken Python, so it failed every safety check on the first try and
    wasted a round-trip on every task."""
    stripped = text.strip()
    if not stripped.startswith("```"):
        return text                            # no wrapper, leave it alone
    lines = stripped.splitlines()[1:]          # drop the opening ``` and its language tag
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]                     # drop the closing ``` if it's there
    return "\n".join(lines)


def _normalize(data, content):
    """Force whatever the AI gave us into the same shape every time, with "script"
    and "explanation" as plain text. Everything downstream assumes those are strings,
    so if the model nested an object in there it would crash far from the real cause."""
    script = data.get("script", "")
    explanation = data.get("explanation", "")
    # [REQUIREMENT: Casting] make sure it's text before anyone uses it.
    script = script if isinstance(script, str) else str(script)
    data["script"] = _strip_code_fence(script)     # and unwrap it if it came in markdown
    data["explanation"] = explanation if isinstance(explanation, str) else str(explanation)
    data.setdefault("raw_response", content)   # keep the original for the report
    return data

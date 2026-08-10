"""
ai_client.py is the only file that talks to the AI model. It sends the model
a question and gets back an answer. We keep this in one place so that if we
ever switch to a different AI provider, we only have to change this one file.
"""

import json
import os
import re

from dotenv import load_dotenv        # a helper library that reads secret settings from a ".env" file.
from openai import OpenAI             # the toolkit we use to talk to the AI model over the internet.
from openai import BadRequestError    # the specific error a server gives when it dislikes our request.


""" This runs first: it opens the .env file and loads its settings so the rest of the program can use them."""
load_dotenv()


DEFAULT_MODEL = "huihui_ai/foundation-sec-abliterated"

"""How long, in seconds, we'll wait for the AI to answer before giving up. A local
model writing a whole script takes a while, so this is generous - but it has to
have *some* limit, or a stalled server would leave this program waiting forever."""
REQUEST_TIMEOUT = 180

"""How much creative freedom the AI gets, from 0 to 1. We keep it low on purpose.
We're not asking for imaginative writing, we're asking for a script in a strict
format, so we want the most predictable answer it can give us rather than a
surprising one."""
TEMPERATURE = 0.2

"""We only want to set up the connection to the AI once and reuse it, instead of
setting it up again every time. This variable is where we keep that saved connection."""
_client = None


def _get_client():
    """We only need to set up the connection once, so we build it the first time
    this function is called, then reuse that same connection every time after.
    The `global` keyword just tells Python "save this for next time" instead of
    throwing it away as soon as the function finishes."""
    global _client
    if _client is None:                  # only build the connection if we haven't already
        """We need to know the web address of the AI server. If that setting is
        missing, we want the program to stop right away with an error, instead of
        quietly trying to connect to nowhere."""
        base_url = os.environ["AI_API_BASE_URL"]      # [REQUIREMENT: Module os]
        """Some AI setups need a secret key to connect, but our local one doesn't.
        So we try to read the key, and if it's missing, we just use a placeholder
        word instead of stopping the program."""
        api_key = os.environ.get("AI_API_KEY", "ollama")
        """Now we actually create the connection to the AI server, using the web
        address and key from above, and save it so we don't have to do this again."""
        _client = OpenAI(base_url=base_url, api_key=api_key, timeout=REQUEST_TIMEOUT)
    return _client                       # give back the saved connection


def _ask(client, model, messages, force_json):
    """Actually send the question. `force_json` asks the server to guarantee the
    reply is valid JSON, which saves us a lot of guesswork later. Not every server
    understands that request, which is why the caller below is ready for it to fail."""
    settings = {"model": model, "messages": messages, "temperature": TEMPERATURE}
    if force_json:
        settings["response_format"] = {"type": "json_object"}
    return client.chat.completions.create(**settings)


def send(system_prompt, user_prompt, model=None):
    """This is the one function everyone else in the program uses to talk to the
    AI. You give it two pieces of text, and it takes care of everything else:
    connecting, sending the question, and turning the answer into something
    the rest of the program can use."""
    client = _get_client()               # reuse the saved connection, or build it if needed
    """Figure out which AI model to use: use the one we were told to use, otherwise
    use the one saved in the settings, otherwise fall back to our default choice."""
    model = model or os.environ.get("AI_MODEL", DEFAULT_MODEL)

    """We send two messages: one that tells the AI how to behave (the "system"
    message), and one with the actual question we want answered (the "user" message)."""
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    try:
        # Preferred: ask the server to force the reply into valid JSON.
        response = _ask(client, model, messages, force_json=True)
    except BadRequestError:
        """The server rejected our request outright, which almost always means this
        version doesn't support the "must be JSON" option. Rather than fail the whole
        run over a nice-to-have, we just ask again the plain way and rely on our own
        parsing below. We only catch this one specific error on purpose - a timeout
        or a connection problem should still be reported, not quietly retried."""
        response = _ask(client, model, messages, force_json=False)

    """The AI's answer comes back packaged inside a bunch of layers. Here we dig
    through those layers to pull out just the plain text of its reply."""
    content = response.choices[0].message.content
    return _parse_response(content)      # turn that plain text into something usable


def _as_dict(text):
    """Try to read some text as a JSON object. Gives back the object if it worked,
    or None if it didn't, so the caller can simply move on to the next approach.

    Note we insist on an *object* specifically. Valid JSON can also be a bare
    string or a list, and those would sail through json.loads and then break
    everything downstream that expects to look up "script" on the result."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None                      # not JSON at all
    return data if isinstance(data, dict) else None


def _parse_response(content):
    """Small AI models don't always give back clean, tidy answers - sometimes they
    wrap the answer in extra explanation or formatting. So we try a few different
    ways of reading the answer, from strictest to most forgiving, until one works."""

    """The model can hand back nothing at all - an empty reply, or literally no text.
    That used to crash the whole program with a confusing error about JSON, so we
    catch it here and return an empty script instead. The validator will then reject
    it with a clear "nothing to run" message, and the normal retry kicks in."""
    if not content:
        return {"script": "", "explanation": "", "raw_response": ""}

    # --- First try: hope the whole answer is already in the clean format we want. ---
    data = _as_dict(content)
    if data is not None:
        return _normalize(data, content)

    """--- Second try: look for the answer tucked inside a code block. ---
    Sometimes the AI wraps its answer in a fenced code block. This searches the
    text for that pattern and pulls out just the part inside it."""
    json_block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if json_block:                       # did we find something that looks like that?
        data = _as_dict(json_block.group(1))
        if data is not None:
            return _normalize(data, content)

    # --- Last resort: give up on finding a clean format, and just treat the reply as the script itself. ---
    code_block = re.search(r"```(?:python)?\s*(.*?)```", content, re.DOTALL)
    script = code_block.group(1).strip() if code_block else content.strip()

    """Hand back the answer in a consistent format, keeping the original raw
    text too, in case we need it later for a report or for troubleshooting."""
    return {"script": script, "explanation": "", "raw_response": content}


def _strip_code_fence(text):
    """Take the markdown wrapper off a script, if the model added one.

    Models are trained to present code in "fences" - three backticks, often with a
    language name like ```python - because that's how code looks on a web page. The
    trouble is it does this *inside* the JSON too, so the script we get reads
    "```python3\\nimport os..." instead of starting at the actual code. That is
    perfectly good JSON and completely invalid Python, so it failed every safety
    check on the first try and cost us a wasted round-trip on every single task."""
    stripped = text.strip()
    if not stripped.startswith("```"):
        return text                            # no wrapper, nothing to do
    lines = stripped.splitlines()[1:]          # drop the opening ``` line and its language tag
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]                     # drop the closing ``` line if it's there
    return "\n".join(lines)


def _normalize(data, content):
    """Make sure whatever the AI gave us always comes back in the same shape, with
    "script" and "explanation" as plain text. Everything downstream - the validator
    and the report - assumes those are strings, so a model that nests an object in
    there would otherwise cause a crash a long way from the actual cause."""
    script = data.get("script", "")
    explanation = data.get("explanation", "")
    # [REQUIREMENT: Casting] force whatever we got into text before anyone uses it.
    script = script if isinstance(script, str) else str(script)
    data["script"] = _strip_code_fence(script)     # ...and unwrap it if it arrived in markdown
    data["explanation"] = explanation if isinstance(explanation, str) else str(explanation)
    data.setdefault("raw_response", content)   # keep the original for the report
    return data

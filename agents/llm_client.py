"""Thin wrapper around the Gemini API for use by agents.

Reads GEMINI_API_KEY from the environment. Never commit a real key.

Uses the current google-genai SDK (google.genai), not the deprecated
google-generativeai (google.generativeai) package.
Install: pip install google-genai
"""

import os
import time

from google import genai
from google.genai import types


def ask_agent(system_prompt: str, user_task: str) -> str:
    """Call the Gemini model and return the text response.

    Retries up to 2 times with exponential backoff on transient errors.
    Raises on persistent failure so callers can handle gracefully.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "GEMINI_API_KEY environment variable is not set. "
            "Export it before running agents."
        )

    client = genai.Client(api_key=api_key)

    max_retries = 2
    delay = 1.0  # seconds

    for attempt in range(max_retries + 1):
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=user_task,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    temperature=0.2,  # Low temperature for more deterministic JSON output
                ),
            )
            return response.text
        except Exception as exc:
            if attempt == max_retries:
                raise RuntimeError(
                    f"Gemini API call failed after {max_retries + 1} attempts: {exc}"
                ) from exc
            time.sleep(delay * (2 ** attempt))

import time
import requests
from django.conf import settings


class AIService:
    def __init__(self, provider="gemini"):
        self.provider = provider

    def query(self, prompt):
        if self.provider == "gemini":
            return self._gemini_query(prompt)
        raise ValueError("Unsupported provider")

    def _gemini_query(self, prompt):
        api_key = settings.GEMINI_API_KEY

        primary_model = getattr(settings, "GEMINI_MODEL", "gemini-2.5-flash")
        fallback_model = getattr(settings, "GEMINI_FALLBACK_MODEL", "gemini-1.5-flash")

        models_to_try = [primary_model]
        if fallback_model and fallback_model != primary_model:
            models_to_try.append(fallback_model)

        last_error = None

        for model_name in models_to_try:
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{model_name}:generateContent?key={api_key}"
            )

            payload = {"contents": [{"parts": [{"text": prompt}]}]}

            delays = [1, 2, 4]

            for attempt, delay in enumerate(delays, start=1):
                try:
                    response = requests.post(url, json=payload, timeout=60)

                    if response.status_code == 503:
                        last_error = Exception(
                            f"Gemini model '{model_name}' unavailable (503). Attempt {attempt}."
                        )
                        if attempt < len(delays):
                            time.sleep(delay)
                            continue

                    response.raise_for_status()
                    data = response.json()

                    try:
                        return data["candidates"][0]["content"]["parts"][0]["text"]
                    except (KeyError, IndexError, TypeError):
                        return str(data)

                except requests.exceptions.RequestException as e:
                    last_error = e
                    if attempt < len(delays):
                        time.sleep(delay)
                        continue

            # if primary model failed after retries, move to fallback model
            continue

        raise Exception(f"All Gemini model attempts failed: {str(last_error)}")

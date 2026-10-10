from openai import OpenAI

from config.api_keys import OPENROUTER_API_KEY, OPENROUTER_MODELS


class OpenRouterClient:
    def __init__(self, use_local=True):
        self.use_local = use_local
        self.local_client = OpenAI(
            base_url="http://localhost:11434/v1",
            api_key="ollama",
            timeout=30.0
        )
        self.local_models = ["qwen2.5:1.5b", "qwen2.5:7b"]

        self.remote_client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=OPENROUTER_API_KEY,
            timeout=15.0
        )
        self.remote_models = OPENROUTER_MODELS

    def generate(self, prompt):
        # 1. Essayer les LLM locaux (Ollama) si activés
        if self.use_local:
            for model in self.local_models:
                try:
                    response = self.local_client.chat.completions.create(
                        model=model,
                        messages=[
                            {
                                "role": "system",
                                "content": (
                                    "You are a cybersecurity SOC analyst. "
                                    "Always answer ONLY with valid JSON. "
                                    "Keep each field concise (2-3 sentences max)."
                                )
                            },
                            {"role": "user", "content": prompt},
                        ],
                        temperature=0,
                        max_tokens=900
                    )
                    return response.choices[0].message.content
                except Exception as e:
                    print(f"[LLM LOCAL] Erreur avec {model}: {e}")

        # 2. Secours vers OpenRouter (Cloud)
        for model in self.remote_models:
            try:
                response = self.remote_client.chat.completions.create(
                    model=model,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are a cybersecurity SOC analyst. "
                                "Always answer ONLY with valid JSON. "
                                "Keep each field concise (2-3 sentences max)."
                            )
                        },
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0,
                    max_tokens=900
                )
                return response.choices[0].message.content
            except Exception as e:
                print(f"[LLM REMOTE] Erreur avec {model}: {e}")

        print("[LLM] Tous les modèles (locaux et cloud) ont échoué. Fallback par défaut appliqué.")
        return None
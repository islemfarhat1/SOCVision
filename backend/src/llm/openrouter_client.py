from openai import OpenAI

from config.api_keys import OPENROUTER_API_KEY, OPENROUTER_MODELS


# Message système par défaut : analyse d'alerte au format JSON
TRIAGE_SYSTEM_PROMPT = (
    "You are a cybersecurity SOC analyst. "
    "Always answer ONLY with valid JSON. "
    "Keep each field concise (2-3 sentences max)."
)


class OpenRouterClient:
    """
    Client LLM : essaie d'abord les modèles locaux (Ollama), puis OpenRouter (cloud).

    Après chaque appel, `last_provider` et `last_model` indiquent le modèle qui a
    réellement répondu (None si tous ont échoué), pour la traçabilité.
    """

    def __init__(self, use_local=True):
        self.use_local = use_local
        self.local_client = OpenAI(
            base_url="http://localhost:11434/v1",
            api_key="ollama",
            timeout=30.0
        )
        self.local_models = ["qwen2.5:1.5b", "qwen2.5:7b"]

        # Client cloud créé seulement si une clé est configurée
        # (OpenAI() lève une erreur sans clé, ce qui cassait LLMService()).
        self.remote_client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=OPENROUTER_API_KEY,
            timeout=15.0
        ) if OPENROUTER_API_KEY else None
        self.remote_models = OPENROUTER_MODELS

        self.last_provider = None
        self.last_model = None

    def generate(self, prompt, system_prompt=TRIAGE_SYSTEM_PROMPT, max_tokens=900):
        self.last_provider = None
        self.last_model = None

        candidates = []
        if self.use_local:
            candidates += [("ollama", self.local_client, m) for m in self.local_models]
        if self.remote_client:
            candidates += [("openrouter", self.remote_client, m) for m in self.remote_models]

        for provider, client, model in candidates:
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0,
                    max_tokens=max_tokens,
                )
                self.last_provider = provider
                self.last_model = model
                return response.choices[0].message.content
            except Exception as e:
                print(f"[LLM {provider}] Erreur avec {model}: {e}")

        print("[LLM] Tous les modèles (locaux et cloud) ont échoué. Fallback par défaut appliqué.")
        return None

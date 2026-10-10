from src.llm.openrouter_client import OpenRouterClient

client = OpenRouterClient()

response = client.generate(
    "Say only: Hello from OpenRouter."
)

print(response)
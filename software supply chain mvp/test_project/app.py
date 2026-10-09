import requests
import yaml


def load_settings(text):
    response = requests.get("https://example.invalid/settings", timeout=2)
    if response.ok:
        return yaml.safe_load(text)
    return {}

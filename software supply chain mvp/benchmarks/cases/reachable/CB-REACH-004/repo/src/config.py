import yaml


def load_config(text):
    return yaml.full_load(text)

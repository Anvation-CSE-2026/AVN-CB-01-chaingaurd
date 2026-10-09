import yaml


def legacy_loader(text):
    return yaml.full_load(text)


print(yaml.safe_load('a: 1'))

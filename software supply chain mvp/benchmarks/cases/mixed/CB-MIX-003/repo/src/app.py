import yaml


def load(text):
    return yaml.full_load(text)


print(load('a: 1'))

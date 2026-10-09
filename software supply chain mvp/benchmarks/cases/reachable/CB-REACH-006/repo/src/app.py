import yaml


def load_all(docs):
    return list(map(yaml.full_load, docs))


print(load_all(['a: 1']))

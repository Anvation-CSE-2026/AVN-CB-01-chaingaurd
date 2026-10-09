import json
import yaml


def read(path):
    with open(path) as fh:
        return json.load(fh)


print(yaml.dump({'a': 1}))

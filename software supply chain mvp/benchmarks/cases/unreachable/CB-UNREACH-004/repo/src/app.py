import yaml

# Do not call yaml.full_load on untrusted input.
"""Docstring mentions yaml.full_load for context only."""


def parse(text):
    return yaml.safe_load(text)


print(parse('a: 1'))

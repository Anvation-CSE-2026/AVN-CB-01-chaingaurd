import yaml


class Parser:
    def parse(self, text):
        return yaml.full_load(text)

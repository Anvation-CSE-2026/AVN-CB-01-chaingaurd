import yaml


class Parser:
    def full_load(self, text):
        return text.strip()


print(Parser().full_load(' a: 1 '))
print(yaml.safe_load('a: 1'))

import yaml


def main():
    return yaml.safe_load('a: 1')


def legacy_loader(text):
    return yaml.full_load(text)


print(main())

import yaml


def main(text):
    return yaml.full_load(text)


if __name__ == '__main__':
    print(main('a: 1'))

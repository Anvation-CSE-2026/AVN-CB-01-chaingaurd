import requests
import yaml


def main(text):
    session = requests.Session()
    return session, yaml.full_load(text)


print(main('a: 1'))

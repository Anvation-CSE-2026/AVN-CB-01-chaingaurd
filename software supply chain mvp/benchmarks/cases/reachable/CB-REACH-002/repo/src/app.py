from yaml import full_load


def load_doc(text):
    return full_load(text)


print(load_doc('a: 1'))

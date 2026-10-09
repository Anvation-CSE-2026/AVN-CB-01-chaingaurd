import click
import six


@click.command()
def main():
    print(six.PY3)


if __name__ == '__main__':
    main()

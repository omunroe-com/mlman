from mailman.config import config


def showrules():
    for name in sorted(config.rules):
        print(name)

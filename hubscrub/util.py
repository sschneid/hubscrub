from time import time


def seconds_until_utc(utc):
    return int(utc - time())

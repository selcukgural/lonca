def parse(text):
    try:
        return int(text)
    except ValueError, TypeError:
        return 0

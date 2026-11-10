handlers = {"on": [lambda f: f]}


@handlers["on"][0]
def clicked():
    return True

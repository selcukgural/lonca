def run(tasks):
    try:
        tasks()
    except* ValueError as group:
        return len(group.exceptions)
    except* OSError:
        return -1
    return 0

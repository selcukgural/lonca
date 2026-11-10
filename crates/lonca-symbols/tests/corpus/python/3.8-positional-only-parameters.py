def clamp(value, low, high, /, *, strict=False):
    return max(low, min(high, value))

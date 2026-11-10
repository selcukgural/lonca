fun <T> orDefault(value: T, fallback: T & Any): T & Any {
    return value ?: fallback
}

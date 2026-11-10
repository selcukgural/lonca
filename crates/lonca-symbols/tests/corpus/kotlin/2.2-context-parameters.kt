class Logger {
    fun log(text: String) {}
}

context(logger: Logger)
fun save(name: String) {
    logger.log(name)
}

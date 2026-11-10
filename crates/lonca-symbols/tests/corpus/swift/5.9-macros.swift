@freestanding(expression)
macro stringify<T>(_ value: T) -> (T, String) = #externalMacro(module: "Macros", type: "StringifyMacro")

func show() -> String {
    return #stringify(1 + 2).1
}

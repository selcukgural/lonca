@freestanding(expression)
macro stringify<T>(_ value: T) -> (T, String) = #externalMacro(module: "Macros", type: "StringifyMacro")

@attached(member)
macro AddInit() = #externalMacro(module: "Macros", type: "AddInitMacro")

@freestanding(expression)
macro log(_ text: String) = #externalMacro(module: "Macros", type: "LogText")

@freestanding(expression)
macro log(_ code: Int) = #externalMacro(module: "Macros", type: "LogCode")

func show() -> String {
    return #stringify(1 + 2).1
}

protocol Shape {
    func area() -> Double
}

func total(_ shapes: [any Shape], extra: some Shape) -> Double {
    return shapes.reduce(extra.area()) { $0 + $1.area() }
}

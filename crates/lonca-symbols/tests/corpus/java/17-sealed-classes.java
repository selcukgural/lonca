sealed interface Shape permits Circle, Square {
    double area();
}

record Circle(double r) implements Shape {
    public double area() {
        return Math.PI * r * r;
    }
}

final class Square implements Shape {
    public double area() {
        return 1;
    }
}

class Describe {
    static String of(Object o) {
        return switch (o) {
            case null -> "null";
            case Integer i when i > 10 -> "large";
            case Integer i -> "small";
            case String s -> s;
            default -> "other";
        };
    }
}

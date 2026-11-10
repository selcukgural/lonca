class Days {
    static int length(String day) {
        return switch (day) {
            case "sat", "sun" -> 0;
            default -> {
                int hours = 8;
                yield hours;
            }
        };
    }
}

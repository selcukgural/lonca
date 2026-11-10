class Shapes {
    static int size(Object o) {
        if (o instanceof String s && !s.isEmpty()) {
            return s.length();
        }
        return 0;
    }
}

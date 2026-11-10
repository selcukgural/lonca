record Pair(Object left, Object right) {}

class Pairs {
    static String show(Object o) {
        if (o instanceof Pair(String l, Integer r)) {
            return l + r;
        }
        return "";
    }
}

import java.util.List;

class Counting {
    static int count(List<String> items) {
        int total = 0;
        for (String _ : items) {
            total++;
        }
        try {
            return Integer.parseInt("1") + total;
        } catch (NumberFormatException _) {
            return total;
        }
    }
}

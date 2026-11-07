package app;

import java.util.List;

/** A client. */
public class Client {
    private int total = 0;

    public Client(int total) {
        this.total = total;
    }

    int charge(int amount) {
        return total + amount;
    }

    int charge(long amount, String why) {
        return total;
    }

    enum State {
        OPEN, SHUT;

        boolean open() {
            return this == OPEN;
        }
    }

    @Test
    void chargesOnce() {
        assert charge(1) == 1;
    }
}

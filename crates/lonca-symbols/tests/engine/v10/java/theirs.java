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
        return total - 1;
    }

    enum State {
        OPEN, SHUT;

        boolean open() {
            return this != SHUT;
        }
    }

    int refund() {
        return 0;
    }

    @Test
    @Disabled
    void chargesOnce() {
        assert charge(1) == 1;
    }
}

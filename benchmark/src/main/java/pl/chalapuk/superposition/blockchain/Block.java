package pl.chalapuk.superposition.blockchain;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Maciej Chałapuk &lt;maciej@chalapuk.pl&gt;.
 */
public class Block {
    public static class Builder {
        private byte[] previousDigest;
        private List<Transaction> transactions = new ArrayList<>();

        public Builder(final byte[] previousDigest) {
            this.previousDigest = previousDigest;
        }

        public void add(final Transaction.Builder transaction) {
            transactions.add(transaction.sign(getLastDigest()));
        }

        public int size() {
            return transactions.size();
        }

        public Block build() {
            return new Block(transactions);
        }

        public byte[] getLastDigest() {
            return transactions.size() == 0 ? previousDigest : transactions.get(transactions.size() - 1).getDigest();
        }
    }

    private final List<Transaction> transactions;

    public Block(final List<Transaction> transactions) {
        this.transactions = transactions;
    }

    public void verify() {
        for (int i = 0; i < transactions.size(); ++i) {
            try {
                transactions.get(i);
            } catch (final Throwable t) {
                throw new RuntimeException("error while verification of " + i + "/" + transactions.size() + " transaction", t);
            }
        }
    }
}

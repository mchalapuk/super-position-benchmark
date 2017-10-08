package pl.chalapuk.superposition.blockchain;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Maciej Chałapuk &lt;maciej@chalapuk.pl&gt;.
 */
public class Block {
    private static final MessageDigest SHA_256_WRITE;
    private static final MessageDigest SHA_256_READ;

    static {
        try {
            SHA_256_WRITE = MessageDigest.getInstance("SHA-256");
            SHA_256_READ = MessageDigest.getInstance("SHA-256");
        } catch (final NoSuchAlgorithmException e) {
            throw new Error(e);
        }
    }

    public static class Builder {
        private final byte[] previousBlockDigest;
        private final List<Transaction> transactions = new ArrayList<>();

        private final byte[] previousMessageDigest;

        public Builder(final byte[] previousBlockDigest,
                       final byte[] previousMessageDigest) {
            this.previousBlockDigest = previousBlockDigest;
            this.previousMessageDigest = previousMessageDigest;
        }

        public void add(final Transaction.Builder transaction) {
            transactions.add(transaction.sign(getLastTransactionDigest()));
        }

        public int size() {
            return transactions.size();
        }

        public Block build() {
            return new Block(previousBlockDigest, transactions, getDigest());
        }

        public byte[] getLastTransactionDigest() {
            return transactions.size() == 0
                    ? previousMessageDigest
                    : transactions.get(transactions.size() - 1).getDigest();
        }

        public byte[] getDigest() {
            return hash(SHA_256_WRITE, previousBlockDigest, transactions);
        }
    }

    private final byte[] previousBlockDigest;
    private final List<Transaction> transactions;
    private final byte[] blockDigest;

    public Block(byte[] previousBlockDigest, final List<Transaction> transactions, final byte[] blockDigest) {
        this.previousBlockDigest = previousBlockDigest;
        this.transactions = transactions;
        this.blockDigest = blockDigest;
    }

    public void verify() {
        verifyDigest();
        verifyTransactions();
    }

    private void verifyDigest() {
        final byte[] calculatedDigest = hash(SHA_256_READ, previousBlockDigest, transactions);
        if (Arrays.equals(calculatedDigest, blockDigest)) {
            throw new RuntimeException("error while verification of block digest");
        }
    }

    private void verifyTransactions() {
        for (int i = 0; i < transactions.size(); ++i) {
            try {
                transactions.get(i).verify();
            } catch (final Throwable t) {
                throw new RuntimeException("error while verification of " + i + "/" + transactions.size() + " transaction", t);
            }
        }
    }

    private static byte[] hash(final MessageDigest digest,
                               final byte[] previousBlockDigest,
                               final List<Transaction> transactions) {
        digest.reset();
        digest.update(previousBlockDigest);
        for (final Transaction t : transactions) {
            digest.update(t.getDigest());
        }
        return digest.digest();
    }
}

package pl.chalapuk.morejuice;

import com.google.caliper.BeforeExperiment;
import com.google.caliper.Benchmark;
import com.google.caliper.Param;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterators;

import java.security.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * @author Maciej Chałapuk &lt;maciej@chalapuk.pl&gt;
 */
@SuppressWarnings("unused")
public class BlockChainBenchmark {

    @Param({"10", "20", "50", "100", "200"})
    public int blockSize;

    @Param({"10", "100", "1000"})
    public int chainLength;

    private static long mark = 0;

    private Iterator<Transaction.Builder> transactionStream;

    private BlockChain chain;
    private Block.Builder pendingBlock;
    private Transaction previous;

    @BeforeExperiment
    public void setUp() throws Exception {
        if (mark != 0) {
            System.out.print(" "+ (System.currentTimeMillis() - mark) / 1000 + " sec ");
        }

        System.out.print("blockSize="+ blockSize +" chainLength="+ chainLength);

        System.out.print(" generating keys...");
        mark = System.currentTimeMillis();
        final List<KeyPair> keys = generateKeys(10);
        System.out.print(" "+ (System.currentTimeMillis() - mark) / 1000 + " sec ");

        System.out.print(" generating transactions...");
        mark = System.currentTimeMillis();
        transactionStream = Iterators.cycle(generateTransactions(keys, 10000000));
        System.out.print(" "+ (System.currentTimeMillis() - mark) / 1000 + " sec ");

        chain = new BlockChain();
        pendingBlock = new Block.Builder();

        final Transaction first = new Transaction(previous, KEYGEN.generateKeyPair(), new byte[] {});
        previous = transactionStream.next().sign(first);
        pendingBlock.add(previous);

        System.out.print(" running benchmark...");
    }

    @Benchmark
    public void singleThread() {
        while (chain.length() != chainLength) {
            while (pendingBlock.size() != blockSize) {
                final Transaction next = transactionStream.next().sign(previous);
                pendingBlock.add(next);
                previous = next;
            }
            chain.add(pendingBlock.verify());
            pendingBlock = new Block.Builder();
        }
    }

    private static class BlockChain {
        private List<Block> blocks = new ArrayList<>();
        private List<byte[]> hashes = new ArrayList<>();

        public void add(final Block block) {
            final byte[] previousHash = hashes.size() == 0 ? new byte[] {} : hashes.get(hashes.size() - 1);
            hashes.add(block.hash(previousHash));
            blocks.add(block);
        }

        public int length() {
            return blocks.size();
        }
    }

    private static class Block {
        public static class Builder {
            private List<Transaction> transactions = new ArrayList<>();

            public void add(final Transaction transaction) {
                transactions.add(transaction);
            }

            public int size() {
                return transactions.size();
            }

            public Block verify() {
                for (Transaction t : transactions) {
                    t.verify();
                }
                return new Block(transactions);
            }
        }

        private List<Transaction> transactions;

        public Block(final List<Transaction> transactions) {
            this.transactions = transactions;
        }

        public byte[] hash(byte[] previousHash) {
            SHA_256.reset();
            SHA_256.update(previousHash);

            for (final Transaction t : transactions) {
                SHA_256.update(t.signedHash);
            }
            return SHA_256.digest();
        }
    }

    private static class Transaction {
        public static class Builder {
            private final KeyPair destination;

            public Builder(final KeyPair destination) {
                this.destination = destination;
            }

            public Transaction sign(final Transaction previous) {
                return new Transaction(previous, destination, sign(previous.destination, previous.signedHash));
            }

            private byte[] sign(final KeyPair source, final byte[] signedHash) {
                try {
                    SIGNATURE.initSign(source.getPrivate());
                    SIGNATURE.update(destination.getPublic().getEncoded());
                    SIGNATURE.update(signedHash);
                    return SIGNATURE.sign();
                } catch (final InvalidKeyException | SignatureException e) {
                    throw new Error(e);
                }
            }
        }

        private final Transaction previous;
        private final KeyPair destination;
        private final byte[] signedHash;

        public Transaction(final Transaction previous, final KeyPair destination, final byte[] signedHash) {
            this.previous = previous;
            this.destination = destination;
            this.signedHash = signedHash;
        }

        public boolean verify() {
            try {
                SIGNATURE.initVerify(previous.destination.getPublic());
                return SIGNATURE.verify(signedHash);
            } catch (final InvalidKeyException | SignatureException e) {
                throw new Error(e);
            }
        }
    }

    private static List<KeyPair> generateKeys(final int n) {
        final ImmutableList.Builder<KeyPair> builder = new ImmutableList.Builder<>();
        for (int i = 0; i < n; ++i) {
            builder.add(KEYGEN.generateKeyPair());
        }

        return builder.build();
    }

    private static List<Transaction.Builder> generateTransactions(final List<KeyPair> keys, final int n) {
        final ImmutableList.Builder<Transaction.Builder> builder = new ImmutableList.Builder<>();
        builder.add(new Transaction.Builder(randomKeyPair(keys)));
        for (int i = 0; i < n; ++i) {
            builder.add(new Transaction.Builder(randomKeyPair(keys)));
        }
        return builder.build();
    }

    private static KeyPair randomKeyPair(final List<KeyPair> keys) {
        return keys.get((int) Math.round(Math.random() * (keys.size() - 1)));
    }

    private static final MessageDigest SHA_256;
    private static final KeyPairGenerator KEYGEN;
    private static final Signature SIGNATURE;

    static {
        try {
            SHA_256 = MessageDigest.getInstance("SHA-256");
            KEYGEN = KeyPairGenerator.getInstance("RSA");
            KEYGEN.initialize(2048);
            SIGNATURE = Signature.getInstance("SHA256WithRSA");
        } catch (final NoSuchAlgorithmException e) {
            throw new Error(e);
        }
    }
}

package pl.chalapuk.morejuice;

import com.google.caliper.BeforeExperiment;
import com.google.caliper.Benchmark;
import com.google.caliper.Param;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterators;
import morejuice.SuperPosition;

import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * @author Maciej Chałapuk &lt;maciej@chalapuk.pl&gt;
 */
@SuppressWarnings("unused")
public class BlockChainBenchmark {
    private static long mark = 0;

    @Param({"10", "50"})
    public int blockSize;

    @Param({"10", "50"})
    public int chainLength;

    private Iterator<Transaction.Builder> transactionStream;

    @BeforeExperiment
    public void setUp() throws Exception {
        if (mark != 0) {
            System.out.println(" "+ (System.currentTimeMillis() - mark) / 1000 + " sec ");
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

        System.out.print(" running benchmark...");
        mark = System.currentTimeMillis();
    }

    @Benchmark
    public void singleThread() {
        final BlockChain chain = new BlockChain();
        Block.Builder pendingBlock = new Block.Builder();

        final Transaction first = new Transaction(null, new byte[] {}, null);
        Transaction previous = transactionStream.next().sign(first);
        pendingBlock.add(previous);

        while (chain.length() != chainLength) {
            while (pendingBlock.size() != blockSize) {
                final Transaction next = transactionStream.next().sign(previous);
                pendingBlock.add(next);
                previous = next;
            }

            chain.add(pendingBlock);
            chain.verifyLastBlock();

            pendingBlock = new Block.Builder();
        }
    }

    @Benchmark
    public void superPosition() throws InterruptedException {
        final SuperPosition<BlockChain> theShit = new SuperPosition<>();
        theShit.initialize(BlockChain::new);

        final Thread signer = new Thread(new Runnable() {
            private final SuperPosition.Mover<BlockChain> mover = theShit.getMover();
            private boolean running = true;

            private Block.Builder newBlock = new Block.Builder();
            private Block.Builder pendingBlock;
            private Transaction previous;

            @Override
            public void run() {
                final Transaction first = new Transaction(null, new byte[] {}, null);
                previous = transactionStream.next().sign(first);
                newBlock.add(previous);

                while (running) {
                    mover.read((chain) -> {
                        while (newBlock.size() != blockSize) {
                            final Transaction next = transactionStream.next().sign(previous);
                            newBlock.add(next);
                            previous = next;
                        }

                        pendingBlock = newBlock;
                        newBlock = new Block.Builder();
                    });

                    mover.move((chain) -> {
                        chain.add(pendingBlock);

                        if (chain.length() + 1 == chainLength) {
                            running = false;
                        }
                    });
                }
            }
        });

        final Thread verifier = new Thread(new Runnable()  {
            private final SuperPosition.Reader<BlockChain> reader = theShit.getReader();
            private boolean running = true;

            @Override
            public void run() {
                while (running && !verify()) {
                    sleep(10);
                }
            }

            private boolean verify() {
                return reader.read((chain) -> {
                    chain.verifyLastBlock();

                    if (chain.length() == chainLength) {
                        running = false;
                    }
                });
            }
        });

        signer.start();
        verifier.start();

        signer.join();
        verifier.join();
    }

    private static class BlockChain {
        private List<Block> blocks = new ArrayList<>();
        private List<byte[]> hashes = new ArrayList<>();

        public void add(final Block.Builder pendingBlock) {
            final byte[] previousDigest = blocks.size() == 0 ? new byte[] {} : blocks.get(blocks.size() - 1).digest;
            blocks.add(pendingBlock.hash(previousDigest));
        }

        public int length() {
            return blocks.size();
        }

        public void verifyLastBlock() {
            if (blocks.size() == 0) {
                throw new IllegalStateException("zero blocks in the chain");
            }

            final byte[] previousDigest = blocks.size() == 1
                    ? new byte[] {}
                    : blocks.get(blocks.size() - 2).getLastTransaction().digest;
            blocks.get(length() - 1).verify(previousDigest);
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

            public Block hash(final byte[] previousDigest) {
                SHA_256.reset();
                SHA_256.update(previousDigest);

                for (final Transaction t : transactions) {
                    SHA_256.update(t.digest);
                    SHA_256.update(t.signature);
                }
                return new Block(transactions, SHA_256.digest());
            }
        }

        private final List<Transaction> transactions;
        private final byte[] digest;

        public Block(final List<Transaction> transactions, final byte[] digest) {
            this.transactions = transactions;
            this.digest = digest;
        }

        public void verify(byte[] previousDigest) {
            for (Transaction t : transactions) {
                t.verify(previousDigest);
                previousDigest = t.digest;
            }
        }

        public Transaction getLastTransaction() {
            return transactions.get(transactions.size() - 1);
        }
    }

    private static class Transaction {
        public static class Builder {
            private final KeyPair source;

            public Builder(final KeyPair source) {
                this.source = source;
            }

            public Transaction sign(final Transaction previous) {
                final byte[] digest = hash(previous.digest, source);
                final byte[] signature = sign(digest);
                return new Transaction(source, digest, signature);
            }

            private byte[] sign(final byte[] digest) {
                try {
                    SIGNATURE.initSign(source.getPrivate());
                    SIGNATURE.update(digest);
                    return SIGNATURE.sign();
                } catch (final InvalidKeyException | SignatureException e) {
                    throw new Error(e);
                }
            }
        }

        private final KeyPair source;
        private final byte[] digest;
        private final byte[] signature;

        public Transaction(final KeyPair source, final byte[] digest, final byte[] signature) {
            this.source = source;
            this.digest = digest;
            this.signature = signature;
        }

        public void verify(final byte[] previousDigest) {
            if (!verifyDigest(previousDigest)) {
                throw new RuntimeException("transaction digest verification failed");
            }
            if (!verifySignature()) {
                throw new RuntimeException("transaction signature verification failed");
            }
        }

        private boolean verifyDigest(byte[] previousDigest) {
            return Arrays.equals(digest, hash(previousDigest, source));
        }

        private boolean verifySignature() {
            try {
                SIGNATURE.initVerify(source.getPublic());
                SIGNATURE.update(this.digest);
                return SIGNATURE.verify(signature);
            } catch (final InvalidKeyException | SignatureException e) {
                throw new Error(e);
            }
        }
    }
    
    private static byte[] hash(final byte[] previousDigest, final KeyPair source) {
        SHA_256.reset();
        SHA_256.update(previousDigest);
        SHA_256.update(source.getPublic().getEncoded());
        return SHA_256.digest();
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
    
    private static void sleep(final long millis) {
        try {
            Thread.sleep(10);
        } catch (final InterruptedException e) {
            throw new Error(e);
        }
    }
}

package pl.chalapuk.superposition;

import com.google.caliper.AfterExperiment;
import com.google.caliper.BeforeExperiment;
import com.google.caliper.Param;
import com.google.caliper.api.Macrobenchmark;
import com.google.caliper.api.VmOptions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterators;
import pl.chalapuk.superposition.blockchain.Block;
import pl.chalapuk.superposition.blockchain.BlockChain;
import pl.chalapuk.superposition.blockchain.Transaction;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.List;

/**
 * @author Maciej Chałapuk &lt;maciej@chalapuk.pl&gt;
 */
@SuppressWarnings({"unused", "SameParameterValue"})
@VmOptions("-XX:-TieredCompilation")
public class BlockChainBenchmark {

    @Param({"10", "20", "30", "40", "50"})
    public int blockSize;
    @Param({"10", "50", "100"})
    public int chainLength;
    @Param
    public Implementation impl;

    private Iterator<Transaction.Builder> transactionStream;

    private static volatile Runnable signerRunnable;
    private static volatile Runnable verifierRunnable;

    private Thread signer;
    private Thread verifier;

    @BeforeExperiment
    public void setUp() throws Exception {
        final List<KeyPair> keys = generateKeys(10);
        transactionStream = Iterators.cycle(generateTransactions(keys, 10000000));

        signer = new Thread() {
            public void run() {
                while (true) {
                    while (signerRunnable == null) {
                        if (this.isInterrupted()) {
                            return;
                        }
                    }
                    signerRunnable.run();
                    signerRunnable = null;
                }
            }
        };

        verifier = new Thread() {
            public void run() {
                while (verifierRunnable == null) {
                    if (this.isInterrupted()) {
                        return;
                    }
                }
                verifierRunnable.run();
                verifierRunnable = null;
            }
        };

        signer.start();
        verifier.start();
    }

    @AfterExperiment
    public void tearDown() throws Exception {
        signer.interrupt();
        verifier.interrupt();
    }

    @Macrobenchmark
    public Object benchmark(final int n) throws Exception {
        Object last = null;

        for (int  i = 0; i < n; ++i) {
            last = impl.run(chainLength, blockSize, transactionStream);
        }
        return last;
    }

    public enum Implementation {
        SINGLE_THREAD {

            @Override
            public Object run(final int chainLength,
                              final int blockSize,
                              final Iterator<Transaction.Builder> transactionStream) {
                final BlockChain chain = new BlockChain();
                Block.Builder pendingBlock = new Block.Builder(new byte[] {});

                while (chain.length() != chainLength) {
                    while (pendingBlock.size() != blockSize) {
                        pendingBlock.add(transactionStream.next());
                    }

                    chain.add(pendingBlock);
                    chain.verifyLastBlock();

                    pendingBlock = new Block.Builder(pendingBlock.getLastDigest());
                }

                return chain;
            }
        },

        SUPER_POSITION {

            @Override
            public Object run(final int chainLength,
                              final int blockSize,
                              final Iterator<Transaction.Builder> transactionStream) throws Exception {
                final SuperPosition<BlockChain> theShit = new SuperPosition<>();
                theShit.initialize(BlockChain::new);

                signerRunnable = new Runnable() {
                    private final SuperPosition.Mover<BlockChain> mover = theShit.getMover();
                    private boolean running = true;

                    private Block.Builder newBlock = new Block.Builder(new byte[] {});
                    private Block.Builder pendingBlock;

                    @Override
                    public void run() {
                        while (running) {
                            mover.read((chain) -> {
                                while (newBlock.size() != blockSize) {
                                    newBlock.add(transactionStream.next());
                                }

                                pendingBlock = newBlock;
                                newBlock = new Block.Builder(pendingBlock.getLastDigest());
                            });

                            mover.move((chain) -> {
                                chain.add(pendingBlock);

                                if (chain.length() + 1 == chainLength) {
                                    running = false;
                                }
                            });
                        }
                    }
                };

                verifierRunnable = new Runnable() {
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
                };

                int count = 0;

                while (signerRunnable != null && verifierRunnable != null) {
                    count += 1;
                    sleep(10);
                }
                return count;
            }
        };

        public abstract Object run(final int chainLength,
                                   final int blockSize,
                                   final Iterator<Transaction.Builder> transactionStream) throws Exception;
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

    private static final KeyPairGenerator KEYGEN;

    static {
        try {
            KEYGEN = KeyPairGenerator.getInstance("RSA");
            KEYGEN.initialize(2048);
        } catch (final NoSuchAlgorithmException e) {
            throw new Error(e);
        }
    }
    
    private static void sleep(final long millis) {
        try {
            Thread.sleep(10);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

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
import java.util.function.Supplier;

/**
 * @author Maciej Chałapuk &lt;maciej@chalapuk.pl&gt;
 */
@SuppressWarnings({"unused", "SameParameterValue"})
@VmOptions("-XX:-TieredCompilation")
public class BlockChainBenchmark {

    @Param({"1", "5", "10", "50", "100", "500"})
    public int blockSize;
    @Param({"5"})
    public int chainLength;
    @Param
    public Implementation impl;

    private Iterator<Transaction.Builder> transactionStream;

    private static volatile Runnable signerRunnable;

    private Thread signer;

    @BeforeExperiment
    public void setUp() throws Exception {
        final List<KeyPair> keys = generateKeys(10);
        transactionStream = Iterators.cycle(generateTransactions(keys, 10000000));

        signer = new Thread() {
            public void run() {
                while (true) {
                    while (signerRunnable == null) {
                        BlockChainBenchmark.sleep(10);
                        if (isInterrupted()) {
                            return;
                        }
                    }
                    signerRunnable.run();
                    signerRunnable = null;
                }
            }
        };

        signer.start();
    }

    @AfterExperiment
    public void tearDown() throws Exception {
        signer.interrupt();
        signer.join();
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
                Block.Builder pendingBlock = new Block.Builder(new byte[] {}, new byte[] {});

                while (chain.length() != chainLength) {
                    while (pendingBlock.size() != blockSize) {
                        pendingBlock.add(transactionStream.next());
                    }

                    chain.add(pendingBlock);
                    chain.verifyLastBlock();

                    pendingBlock = new Block.Builder(
                            pendingBlock.getDigest(),
                            pendingBlock.getLastTransactionDigest()
                    );
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

                final SuperPosition.Mover<BlockChain> mover = theShit.getMover();
                final SuperPosition.Reader<BlockChain> reader = theShit.getReader();

                signerRunnable = new Runnable() {
                    private boolean running = true;

                    private Block.Builder newBlock = new Block.Builder(new byte[] {}, new byte[] {});
                    private Block.Builder pendingBlock;

                    @Override
                    public void run() {
                        while (running) {
                            mover.read((chain) -> {
                                while (newBlock.size() != blockSize) {
                                    newBlock.add(transactionStream.next());
                                }

                                pendingBlock = newBlock;
                                newBlock = new Block.Builder(
                                        pendingBlock.getDigest(),
                                        pendingBlock.getLastTransactionDigest()
                                );
                            });

                            mover.move((chain) -> {
                                chain.add(pendingBlock);

                                if (chain.length() == chainLength) {
                                    running = false;
                                }
                            });
                        }
                    }
                };

                final Supplier<Integer> verifierRunnable = new Supplier<Integer>() {
                    private int lastVerifiedBlock = -1;

                    @Override
                    public Integer get() {
                        while (true) {
                            reader.read((chain) -> {
                                chain.verifyBlocksSince(lastVerifiedBlock + 1);
                                lastVerifiedBlock = chain.length();
                            });

                            if (lastVerifiedBlock > chainLength) {
                                throw new Error("lastVerifiedBlock="+ lastVerifiedBlock +" > chainLength="+ chainLength);
                            }
                            if (lastVerifiedBlock == chainLength) {
                                break;
                            }
                        }
                        return lastVerifiedBlock;
                    }
                };

                return verifierRunnable.get();
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

    private static void sleep(int millis) {
        try {
            Thread.sleep(millis);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
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
}

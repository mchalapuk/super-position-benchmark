package pl.chalapuk.superposition.blockchain;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Maciej Chałapuk &lt;maciej@chalapuk.pl&gt;.
 */
public class BlockChain {
    private List<Block> blocks = new ArrayList<>();

    public void add(final Block.Builder pendingBlock) {
        blocks.add(pendingBlock.build());
    }

    public int length() {
        return blocks.size();
    }

    public void verifyLastBlock() {
        if (blocks.size() == 0) {
            throw new IllegalStateException("zero blocks in the chain");
        }

        try {
            blocks.get(length() - 1).verify();
        } catch (final Throwable t) {
            throw new RuntimeException("error while verification of " + (length() - 1) + " block", t);
        }
    }
}

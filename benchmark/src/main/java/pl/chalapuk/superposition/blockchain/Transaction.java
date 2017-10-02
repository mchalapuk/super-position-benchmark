package pl.chalapuk.superposition.blockchain;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * @author Maciej Chałapuk &lt;maciej@chalapuk.pl&gt;.
 */
public class Transaction {
    private static final Signature SIGNATURE_WRITE;
    private static final Signature SIGNATURE_READ;
    private static final MessageDigest SHA_256_WRITE;
    private static final MessageDigest SHA_256_READ;

    static {
        try {
            SIGNATURE_WRITE = Signature.getInstance("SHA256WithRSA");
            SIGNATURE_READ = Signature.getInstance("SHA256WithRSA");
            SHA_256_WRITE = MessageDigest.getInstance("SHA-256");
            SHA_256_READ = MessageDigest.getInstance("SHA-256");
        } catch (final NoSuchAlgorithmException e) {
            throw new Error(e);
        }
    }
    public static class Builder {
        private final KeyPair source;

        public Builder(final KeyPair source) {
            this.source = source;
        }

        public Transaction sign(final byte[] previousDigest) {
            final byte[] digest = hash(SHA_256_WRITE, previousDigest, source);

            try {
                SIGNATURE_WRITE.initSign(source.getPrivate());
                SIGNATURE_WRITE.update(digest);
                return new Transaction(source, previousDigest, digest, SIGNATURE_WRITE.sign());
            } catch (final InvalidKeyException | SignatureException e) {
                throw new Error(e);
            }
        }
    }

    private final KeyPair source;
    private final byte[] previousDigest;
    private final byte[] digest;
    private final byte[] signature;

    public Transaction(final KeyPair source, final byte[] previousDigest, final byte[] digest, final byte[] signature) {
        this.source = source;
        this.digest = digest;
        this.previousDigest = previousDigest;
        this.signature = signature;
    }

    public void verify() {
        verifyDigest();
        verifySignature();
    }

    public byte[] getDigest() {
        return digest;
    }

    private void verifyDigest() {
        final byte[] calculated = hash(SHA_256_READ, previousDigest, source);
        if (!Arrays.equals(digest, calculated)) {
            throw new RuntimeException("transaction digest verification failed\nstored: " +
                Arrays.toString(digest) + "\ncalculated: " + Arrays.toString(calculated) + "\n");
        }
    }

    private void verifySignature() {
        try {
            SIGNATURE_READ.initVerify(source.getPublic());
            SIGNATURE_READ.update(digest);
            if (!SIGNATURE_READ.verify(signature)) {
                throw new RuntimeException("transaction signature verification failed");
            }
        } catch (final InvalidKeyException | SignatureException e) {
            throw new Error(e);
        }
    }

    private static byte[] hash(final MessageDigest digest, final byte[] previousDigest, final KeyPair source) {
        digest.reset();
        digest.update(previousDigest);
        digest.update(source.getPublic().getEncoded());
        return digest.digest();
    }
}

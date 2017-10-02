package pl.chalapuk.superposition.superposition

import pl.chalapuk.superposition.blockchain.Transaction
import spock.lang.Specification

import java.security.KeyPairGenerator

/**
 * @author Maciej Chałapuk &lt;maciej@chalapuk.pl&gt;.
 */
class TransactionSpec extends Specification {
    private static final KeyPairGenerator KEYGEN = KeyPairGenerator.getInstance("RSA")

    static {
        KEYGEN.initialize(2048)
    }

    def "verifies signature"() {
        given:
        def transaction0 = new Transaction.Builder(KEYGEN.generateKeyPair()).sign(new byte[0])
        def transaction1 = new Transaction.Builder(KEYGEN.generateKeyPair()).sign(new byte[0])

        when:
        transaction0.verify()
        transaction1.verify()

        then:
        noExceptionThrown()
    }
}

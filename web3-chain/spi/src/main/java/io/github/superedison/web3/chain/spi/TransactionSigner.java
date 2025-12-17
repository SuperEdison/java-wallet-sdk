package io.github.superedison.web3.chain.spi;

import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.core.tx.RawTransaction;
import io.github.superedison.web3.core.tx.SignedTransaction;

/**
 * 可选的签名器抽象，封装 encode -> hash -> sign -> assemble。
 */
public interface TransactionSigner<
        TX extends RawTransaction,
        STX extends SignedTransaction<TX>
        > {

    STX sign(TX tx, SigningKey key);
}

package io.github.superedison.web3.chain.spi;

import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.core.tx.RawTransaction;
import io.github.superedison.web3.core.tx.SignedTransaction;

/**
 * ChainAdapter 定义了“某条链如何从意图得到可广播交易”的最小 SPI。
 */
public interface ChainAdapter<
        TX extends RawTransaction,
        STX extends SignedTransaction<TX>
        > {

    /**
     * 当前适配的链类型。
     */
    ChainType chainType();

    /**
     * 执行签名流程（encode -> hash -> sign -> assemble）。
     */
    STX sign(TX tx, SigningKey key);

    /**
     * 可直接广播的最终字节。
     */
    byte[] rawBytes(STX signedTx);

    /**
     * 交易哈希 / txHash。
     */
    byte[] txHash(STX signedTx);
}

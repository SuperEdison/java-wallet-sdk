package io.github.superedison.web3.chain.tron;

import io.github.superedison.web3.chain.spi.ChainAdapter;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.chain.tron.internal.TronTransactionEncoder;
import io.github.superedison.web3.chain.tron.internal.TronTransactionHasher;
import io.github.superedison.web3.chain.tron.internal.TronTransactionSigner;
import io.github.superedison.web3.chain.tron.tx.TronRawTransaction;
import io.github.superedison.web3.chain.tron.tx.TronSignedTransaction;
import io.github.superedison.web3.core.signer.SigningKey;

/**
 * TRON ChainAdapter：按 SPI 完成 encode -> hash -> sign -> assemble。
 */
public final class TronChainAdapter implements ChainAdapter<TronRawTransaction, TronSignedTransaction> {

    private final TronTransactionEncoder encoder;
    private final TronTransactionHasher hasher;
    private final TronTransactionSigner signer;

    public TronChainAdapter() {
        this.encoder = new TronTransactionEncoder();
        this.hasher = new TronTransactionHasher();
        this.signer = new TronTransactionSigner(encoder, hasher);
    }

    @Override
    public ChainType chainType() {
        return ChainType.TRON;
    }

    @Override
    public TronSignedTransaction sign(TronRawTransaction tx, SigningKey key) {
        return signer.sign(tx, key);
    }

    @Override
    public byte[] rawBytes(TronSignedTransaction signedTx) {
        return signedTx.rawBytes();
    }

    @Override
    public byte[] txHash(TronSignedTransaction signedTx) {
        return signedTx.txHash();
    }
}

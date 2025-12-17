package io.github.superedison.web3.chain.evm;

import io.github.superedison.web3.chain.evm.internal.EvmTransactionEncoder;
import io.github.superedison.web3.chain.evm.internal.EvmTransactionHasher;
import io.github.superedison.web3.chain.evm.internal.EvmTransactionSigner;
import io.github.superedison.web3.chain.evm.tx.EvmRawTransaction;
import io.github.superedison.web3.chain.evm.tx.EvmSignedTransaction;
import io.github.superedison.web3.chain.spi.ChainAdapter;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.core.signer.SigningKey;

/**
 * EVM ChainAdapter：按 SPI 完成 encode -> hash -> sign -> assemble。
 */
public final class EvmChainAdapter implements ChainAdapter<EvmRawTransaction, EvmSignedTransaction> {

    private final EvmTransactionEncoder encoder;
    private final EvmTransactionHasher hasher;
    private final EvmTransactionSigner signer;

    public EvmChainAdapter() {
        this.encoder = new EvmTransactionEncoder();
        this.hasher = new EvmTransactionHasher();
        this.signer = new EvmTransactionSigner(encoder, hasher);
    }

    @Override
    public ChainType chainType() {
        return ChainType.EVM;
    }

    @Override
    public EvmSignedTransaction sign(EvmRawTransaction tx, SigningKey key) {
        return signer.sign(tx, key);
    }

    @Override
    public byte[] rawBytes(EvmSignedTransaction signedTx) {
        return signedTx.rawBytes();
    }

    @Override
    public byte[] txHash(EvmSignedTransaction signedTx) {
        return signedTx.txHash();
    }
}

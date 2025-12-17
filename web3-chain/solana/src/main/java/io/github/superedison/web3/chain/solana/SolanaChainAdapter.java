package io.github.superedison.web3.chain.solana;

import io.github.superedison.web3.chain.solana.internal.SolanaTransactionEncoder;
import io.github.superedison.web3.chain.solana.internal.SolanaTransactionHasher;
import io.github.superedison.web3.chain.solana.internal.SolanaTransactionSigner;
import io.github.superedison.web3.chain.solana.tx.SolanaRawTransaction;
import io.github.superedison.web3.chain.solana.tx.SolanaSignedTransaction;
import io.github.superedison.web3.chain.spi.ChainAdapter;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.core.signer.SigningKey;

/**
 * Solana ChainAdapter：按 SPI 完成 encode -> sign -> assemble。
 *
 * Solana 使用 Ed25519 签名算法，地址直接是公钥的 Base58 编码。
 * 交易哈希就是第一个签名的 Base58 编码。
 */
public final class SolanaChainAdapter implements ChainAdapter<SolanaRawTransaction, SolanaSignedTransaction> {

    private final SolanaTransactionEncoder encoder;
    private final SolanaTransactionHasher hasher;
    private final SolanaTransactionSigner signer;

    public SolanaChainAdapter() {
        this.encoder = new SolanaTransactionEncoder();
        this.hasher = new SolanaTransactionHasher();
        this.signer = new SolanaTransactionSigner(encoder);
    }

    @Override
    public ChainType chainType() {
        return ChainType.SOL;
    }

    @Override
    public SolanaSignedTransaction sign(SolanaRawTransaction tx, SigningKey key) {
        return signer.sign(tx, key);
    }

    @Override
    public byte[] rawBytes(SolanaSignedTransaction signedTx) {
        return signedTx.rawBytes();
    }

    @Override
    public byte[] txHash(SolanaSignedTransaction signedTx) {
        return signedTx.txHash();
    }
}

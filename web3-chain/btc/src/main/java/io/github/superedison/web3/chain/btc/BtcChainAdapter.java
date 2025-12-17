package io.github.superedison.web3.chain.btc;

import io.github.superedison.web3.chain.btc.address.BtcNetwork;
import io.github.superedison.web3.chain.btc.internal.BtcTransactionEncoder;
import io.github.superedison.web3.chain.btc.internal.BtcTransactionHasher;
import io.github.superedison.web3.chain.btc.internal.BtcTransactionSigner;
import io.github.superedison.web3.chain.btc.tx.BtcRawTransaction;
import io.github.superedison.web3.chain.btc.tx.BtcSignedTransaction;
import io.github.superedison.web3.chain.spi.ChainAdapter;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.core.signer.SigningKey;

/**
 * Bitcoin ChainAdapter：按 SPI 完成 encode -> hash -> sign -> assemble。
 *
 * 支持多种地址类型：
 * - Legacy P2PKH (以 '1' 开头)
 * - Wrapped SegWit P2SH-P2WPKH (以 '3' 开头)
 * - Native SegWit P2WPKH/P2WSH (以 'bc1q' 开头)
 * - Taproot P2TR (以 'bc1p' 开头)
 *
 * 默认使用主网，可以通过构造函数指定网络
 */
public final class BtcChainAdapter implements ChainAdapter<BtcRawTransaction, BtcSignedTransaction> {

    private final BtcTransactionEncoder encoder;
    private final BtcTransactionHasher hasher;
    private final BtcTransactionSigner signer;
    private final BtcNetwork network;

    /**
     * 创建主网适配器
     */
    public BtcChainAdapter() {
        this(BtcNetwork.MAINNET);
    }

    /**
     * 创建指定网络的适配器
     */
    public BtcChainAdapter(BtcNetwork network) {
        this.network = network;
        this.encoder = new BtcTransactionEncoder();
        this.hasher = new BtcTransactionHasher();
        this.signer = new BtcTransactionSigner(encoder, hasher, network);
    }

    @Override
    public ChainType chainType() {
        return ChainType.BTC;
    }

    @Override
    public BtcSignedTransaction sign(BtcRawTransaction tx, SigningKey key) {
        return signer.sign(tx, key);
    }

    @Override
    public byte[] rawBytes(BtcSignedTransaction signedTx) {
        return signedTx.rawBytes();
    }

    @Override
    public byte[] txHash(BtcSignedTransaction signedTx) {
        return signedTx.txHash();
    }

    /**
     * 获取当前网络
     */
    public BtcNetwork getNetwork() {
        return network;
    }

    /**
     * 获取编码器
     */
    public BtcTransactionEncoder getEncoder() {
        return encoder;
    }

    /**
     * 获取哈希器
     */
    public BtcTransactionHasher getHasher() {
        return hasher;
    }
}

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
 * Bitcoin ChainAdapter：按 SPI 完成 encode -&gt; hash -&gt; sign -&gt; assemble。
 *
 * 0.1.0 支持签名的输入类型：
 * <ul>
 *   <li>Legacy P2PKH（以 '1' 开头）</li>
 *   <li>Wrapped SegWit P2SH-P2WPKH（以 '3' 开头）—— 输入需提供 amount 与 P2SH scriptPubKey，
 *       签名器会严格校验 hash 等于 hash160(0x00 0x14 hash160(pubkey))，不匹配立即拒绝。</li>
 *   <li>Native SegWit P2WPKH（以 'bc1q' 开头）—— 输入需提供 amount（BIP-143）与 scriptPubKey，
 *       签名器会严格校验 scriptPubKey 的 20-byte hash 属于当前签名密钥。</li>
 * </ul>
 *
 * <p>不支持的输入类型（包括 P2WSH、Taproot P2TR、空 scriptPubKey 等）会在签名时抛
 * {@link IllegalArgumentException}。Taproot 完整支持（BIP-340 / BIP-341）计划于 0.2.0 提供。
 *
 * <p>默认使用主网，可以通过构造函数指定网络。
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

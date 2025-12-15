package io.github.superedison.web3.chain;

import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.transaction.RawTransaction;
import io.github.superedison.web3.core.transaction.SignedTransaction;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.HDWallet;
import io.github.superedison.web3.core.wallet.Wallet;

import java.util.List;

/**
 * 链适配器 SPI
 * 由 web3-chain-* 模块实现
 */
public interface ChainAdapter {

    /**
     * 获取链类型
     */
    ChainType getChainType();

    // ========== 地址 ==========

    /**
     * 验证地址格式
     */
    boolean isValidAddress(String address);

    /**
     * 解析地址
     */
    Address parseAddress(String address);

    /**
     * 从公钥派生地址
     */
    Address deriveAddress(byte[] publicKey);

    // ========== 钱包 ==========

    /**
     * 创建 HD 钱包
     */
    HDWallet createHDWallet(int wordCount);

    /**
     * 从助记词恢复
     */
    HDWallet fromMnemonic(List<String> mnemonic, String passphrase, String path);

    /**
     * 从私钥创建
     */
    Wallet fromPrivateKey(byte[] privateKey);

    // ========== 交易 ==========

    /**
     * 编码交易（用于签名）
     */
    byte[] encodeTransaction(RawTransaction transaction);

    /**
     * 计算交易哈希
     */
    byte[] hashTransaction(RawTransaction transaction);

    /**
     * 编码已签名交易（用于广播）
     */
    byte[] encodeSignedTransaction(SignedTransaction transaction);

    // ========== 签名 ==========

    /**
     * 从签名恢复地址
     */
    Address recoverSigner(byte[] hash, Signature signature);

    /**
     * 哈希消息（链特定前缀）
     */
    byte[] hashMessage(byte[] message);
}
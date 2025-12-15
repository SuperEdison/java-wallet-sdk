package io.github.superedison.web3.client;

import io.github.superedison.web3.chain.ChainAdapter;
import io.github.superedison.web3.chain.ChainType;
import io.github.superedison.web3.client.config.ClientConfig;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.transaction.RawTransaction;
import io.github.superedison.web3.core.transaction.SignedTransaction;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.HDWallet;
import io.github.superedison.web3.core.wallet.Wallet;

import java.util.List;

/**
 * Web3 客户端
 * SDK 统一入口，委托给对应的 ChainAdapter
 */
public final class Web3Client {

    private final ChainAdapterRegistry registry;
    private final ClientConfig config;

    private Web3Client(ChainAdapterRegistry registry, ClientConfig config) {
        this.registry = registry;
        this.config = config;
    }

    // ========== 地址 ==========

    /**
     * 验证地址格式
     */
    public boolean isValidAddress(ChainType chainType, String address) {
        return registry.get(chainType).isValidAddress(address);
    }

    /**
     * 解析地址
     */
    public Address parseAddress(ChainType chainType, String address) {
        return registry.get(chainType).parseAddress(address);
    }

    /**
     * 从公钥派生地址
     */
    public Address deriveAddress(ChainType chainType, byte[] publicKey) {
        return registry.get(chainType).deriveAddress(publicKey);
    }

    // ========== 钱包 ==========

    /**
     * 创建 HD 钱包
     */
    public HDWallet createHDWallet(ChainType chainType, int wordCount) {
        return registry.get(chainType).createHDWallet(wordCount);
    }

    /**
     * 从助记词恢复
     */
    public HDWallet fromMnemonic(ChainType chainType, List<String> mnemonic, String passphrase, String path) {
        return registry.get(chainType).fromMnemonic(mnemonic, passphrase, path);
    }

    /**
     * 从私钥创建
     */
    public Wallet fromPrivateKey(ChainType chainType, byte[] privateKey) {
        return registry.get(chainType).fromPrivateKey(privateKey);
    }

    // ========== 交易 ==========

    /**
     * 编码交易（用于签名）
     */
    public byte[] encodeTransaction(ChainType chainType, RawTransaction transaction) {
        return registry.get(chainType).encodeTransaction(transaction);
    }

    /**
     * 计算交易哈希
     */
    public byte[] hashTransaction(ChainType chainType, RawTransaction transaction) {
        return registry.get(chainType).hashTransaction(transaction);
    }

    /**
     * 编码已签名交易（用于广播）
     */
    public byte[] encodeSignedTransaction(ChainType chainType, SignedTransaction transaction) {
        return registry.get(chainType).encodeSignedTransaction(transaction);
    }

    // ========== 签名 ==========

    /**
     * 计算消息哈希（链特定前缀）
     */
    public byte[] hashMessage(ChainType chainType, byte[] message) {
        return registry.get(chainType).hashMessage(message);
    }

    /**
     * 从签名恢复地址
     */
    public Address recoverSigner(ChainType chainType, byte[] hash, Signature signature) {
        return registry.get(chainType).recoverSigner(hash, signature);
    }

    // ========== 适配器访问 ==========

    /**
     * 获取指定链的适配器
     */
    public ChainAdapter adapter(ChainType chainType) {
        return registry.get(chainType);
    }

    /**
     * 检查是否支持指定链
     */
    public boolean supports(ChainType chainType) {
        return registry.supports(chainType);
    }

    // ========== Builder ==========

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private ChainAdapterRegistry registry;
        private ClientConfig config;

        /**
         * 使用指定的注册表
         */
        public Builder registry(ChainAdapterRegistry registry) {
            this.registry = registry;
            return this;
        }

        /**
         * 使用指定的配置
         */
        public Builder config(ClientConfig config) {
            this.config = config;
            return this;
        }

        /**
         * 注册适配器
         */
        public Builder register(ChainAdapter adapter) {
            if (this.registry == null) {
                this.registry = ChainAdapterRegistry.create();
            }
            this.registry.register(adapter);
            return this;
        }

        /**
         * 自动发现适配器
         */
        public Builder autoDiscover() {
            if (this.registry == null) {
                this.registry = ChainAdapterRegistry.create();
            }
            this.registry.autoDiscover();
            return this;
        }

        public Web3Client build() {
            if (this.registry == null) {
                this.registry = ChainAdapterRegistry.create();
            }
            if (this.config == null) {
                this.config = ClientConfig.create();
            }
            return new Web3Client(registry, config);
        }
    }
}
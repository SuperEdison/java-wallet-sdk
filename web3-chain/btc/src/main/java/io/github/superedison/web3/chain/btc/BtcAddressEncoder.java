package io.github.superedison.web3.chain.btc;

import io.github.superedison.web3.chain.btc.address.*;
import io.github.superedison.web3.chain.spi.AddressEncoder;
import io.github.superedison.web3.chain.spi.ChainType;

/**
 * Bitcoin 地址编码器
 *
 * 支持多种 BTC 地址类型：
 * - P2PKH (Legacy, 1...)
 * - P2SH-P2WPKH (Wrapped SegWit, 3...)
 * - P2WPKH (Native SegWit, bc1q...)
 * - P2TR (Taproot, bc1p...)
 *
 * 默认生成 Native SegWit (P2WPKH) 地址
 */
public final class BtcAddressEncoder implements AddressEncoder {

    @Override
    public ChainType chainType() {
        return ChainType.BTC;
    }

    /**
     * 编码公钥为 BTC 地址（默认 P2WPKH 主网）
     *
     * @param publicKey 33 字节压缩公钥
     * @return Native SegWit 地址 (bc1q...)
     */
    @Override
    public String encode(byte[] publicKey) {
        return encode(publicKey, new BtcAddressOptions(BtcAddressType.P2WPKH, BtcNetwork.MAINNET));
    }

    /**
     * 编码公钥为指定类型的 BTC 地址
     *
     * @param publicKey 33 字节压缩公钥
     * @param options   BtcAddressOptions 包含地址类型和网络
     * @return 格式化的 BTC 地址
     */
    @Override
    public String encode(byte[] publicKey, Object options) {
        if (!(options instanceof BtcAddressOptions opts)) {
            throw new IllegalArgumentException("Options must be BtcAddressOptions");
        }

        BtcAddressType type = opts.type() != null ? opts.type() : BtcAddressType.P2WPKH;
        BtcNetwork network = opts.network() != null ? opts.network() : BtcNetwork.MAINNET;

        return switch (type) {
            case P2PKH -> P2PKHAddress.fromPublicKey(publicKey, network).toBase58();
            case P2SH_P2WPKH -> P2SHAddress.fromPublicKeyP2WPKH(publicKey, network).toBase58();
            case P2WPKH -> Bech32Address.p2wpkhFromPublicKey(publicKey, network).toBech32();
            case P2WSH -> throw new IllegalArgumentException("P2WSH requires script, not public key");
            case P2TR -> TaprootAddress.fromPublicKey(publicKey, network).toBech32m();
        };
    }

    @Override
    public PublicKeyFormat requiredFormat() {
        return PublicKeyFormat.COMPRESSED_33;
    }

    /**
     * BTC 地址选项
     *
     * @param type    地址类型
     * @param network 网络（主网/测试网）
     */
    public record BtcAddressOptions(BtcAddressType type, BtcNetwork network) {

        /**
         * 创建主网选项
         */
        public static BtcAddressOptions mainnet(BtcAddressType type) {
            return new BtcAddressOptions(type, BtcNetwork.MAINNET);
        }

        /**
         * 创建测试网选项
         */
        public static BtcAddressOptions testnet(BtcAddressType type) {
            return new BtcAddressOptions(type, BtcNetwork.TESTNET);
        }

        /**
         * 默认选项（P2WPKH 主网）
         */
        public static BtcAddressOptions defaults() {
            return new BtcAddressOptions(BtcAddressType.P2WPKH, BtcNetwork.MAINNET);
        }
    }
}

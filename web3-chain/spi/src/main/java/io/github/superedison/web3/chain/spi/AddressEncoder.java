package io.github.superedison.web3.chain.spi;

/**
 * 地址编码器 SPI
 *
 * 将公钥编码为链特定格式的地址。
 * 每个链实现自己的 AddressEncoder。
 *
 * 使用示例：
 * <pre>{@code
 * AddressEncoder encoder = AddressEncoderRegistry.get(ChainType.EVM);
 * String address = encoder.encode(publicKey);
 * }</pre>
 */
public interface AddressEncoder {

    /**
     * 支持的链类型
     */
    ChainType chainType();

    /**
     * 将公钥编码为地址
     *
     * @param publicKey 公钥字节数组（格式由 requiredFormat() 指定）
     * @return 格式化的地址字符串
     */
    String encode(byte[] publicKey);

    /**
     * 将公钥编码为地址（带选项）
     *
     * 用于支持多种地址类型的链（如 BTC）
     *
     * @param publicKey 公钥字节数组
     * @param options   链特定选项（如 BTC 地址类型、网络等）
     * @return 格式化的地址字符串
     */
    default String encode(byte[] publicKey, Object options) {
        return encode(publicKey);
    }

    /**
     * 获取所需的公钥格式
     */
    PublicKeyFormat requiredFormat();

    /**
     * 公钥格式枚举
     */
    enum PublicKeyFormat {
        /**
         * 非压缩公钥 (65 字节: 04 + x + y)
         * 用于 EVM, TRON
         */
        UNCOMPRESSED_65,

        /**
         * 压缩公钥 (33 字节: 02/03 + x)
         * 用于 BTC
         */
        COMPRESSED_33,

        /**
         * Ed25519 公钥 (32 字节)
         * 用于 Solana, NEAR, Aptos
         */
        ED25519_32
    }
}

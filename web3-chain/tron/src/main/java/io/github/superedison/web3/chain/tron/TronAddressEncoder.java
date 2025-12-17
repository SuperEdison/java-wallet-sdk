package io.github.superedison.web3.chain.tron;

import io.github.superedison.web3.chain.spi.AddressEncoder;
import io.github.superedison.web3.chain.spi.ChainType;
import io.github.superedison.web3.chain.tron.address.TronAddress;

/**
 * TRON 地址编码器
 *
 * 将 secp256k1 公钥编码为 TRON 地址（Base58Check 格式，T 开头）
 */
public final class TronAddressEncoder implements AddressEncoder {

    @Override
    public ChainType chainType() {
        return ChainType.TRON;
    }

    /**
     * 编码公钥为 TRON 地址
     *
     * @param publicKey 65 字节非压缩公钥 (04 + x + y) 或 64 字节 (x + y)
     * @return Base58Check 编码的地址 (T...)
     */
    @Override
    public String encode(byte[] publicKey) {
        TronAddress address = TronAddress.fromPublicKey(publicKey);
        return address.toBase58();
    }

    @Override
    public PublicKeyFormat requiredFormat() {
        return PublicKeyFormat.UNCOMPRESSED_65;
    }
}

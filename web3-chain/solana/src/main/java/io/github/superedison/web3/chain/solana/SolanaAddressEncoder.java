package io.github.superedison.web3.chain.solana;

import io.github.superedison.web3.chain.solana.address.SolanaAddress;
import io.github.superedison.web3.chain.spi.AddressEncoder;
import io.github.superedison.web3.chain.spi.ChainType;

/**
 * Solana 地址编码器
 *
 * 将 Ed25519 公钥编码为 Solana 地址（Base58 格式）
 * Solana 地址就是公钥本身的 Base58 编码
 */
public final class SolanaAddressEncoder implements AddressEncoder {

    @Override
    public ChainType chainType() {
        return ChainType.SOL;
    }

    /**
     * 编码公钥为 Solana 地址
     *
     * @param publicKey 32 字节 Ed25519 公钥
     * @return Base58 编码的地址
     */
    @Override
    public String encode(byte[] publicKey) {
        SolanaAddress address = SolanaAddress.fromPublicKey(publicKey);
        return address.toBase58();
    }

    @Override
    public PublicKeyFormat requiredFormat() {
        return PublicKeyFormat.ED25519_32;
    }
}

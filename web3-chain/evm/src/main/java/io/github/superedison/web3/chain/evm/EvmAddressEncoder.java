package io.github.superedison.web3.chain.evm;

import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.chain.spi.AddressEncoder;
import io.github.superedison.web3.chain.spi.ChainType;

/**
 * EVM 地址编码器
 *
 * 将 secp256k1 公钥编码为 EVM 地址（EIP-55 校验和格式）
 */
public final class EvmAddressEncoder implements AddressEncoder {

    @Override
    public ChainType chainType() {
        return ChainType.EVM;
    }

    /**
     * 编码公钥为 EVM 地址
     *
     * @param publicKey 65 字节非压缩公钥 (04 + x + y) 或 64 字节 (x + y)
     * @return EIP-55 校验和格式的地址 (0x...)
     */
    @Override
    public String encode(byte[] publicKey) {
        EvmAddress address = EvmAddress.fromPublicKey(publicKey);
        return address.toChecksumHex();
    }

    @Override
    public PublicKeyFormat requiredFormat() {
        return PublicKeyFormat.UNCOMPRESSED_65;
    }
}

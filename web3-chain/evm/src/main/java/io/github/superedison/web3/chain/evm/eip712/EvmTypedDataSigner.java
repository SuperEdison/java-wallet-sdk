package io.github.superedison.web3.chain.evm.eip712;

import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.chain.evm.address.Eip55Checksum;
import io.github.superedison.web3.chain.exception.AddressException;
import io.github.superedison.web3.chain.evm.internal.EvmSignature;
import io.github.superedison.web3.chain.spi.signing.Secp256k1SignatureValidator;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.eip712.AddressCodec;
import io.github.superedison.web3.crypto.eip712.Eip712Encoder;
import io.github.superedison.web3.crypto.eip712.Eip712TypedData;

/**
 * EVM EIP-712 结构化数据签名器（对齐 {@code eth_signTypedData} / ethers {@code signTypedData}）。
 *
 * <p>复用 {@link Eip712Encoder}（与 TRON 共用一份编码逻辑），注入 EVM 地址编解码（0x-hex / {@link EvmAddress}）。
 * 摘要 = {@code keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(message))}，再用 secp256k1 签出
 * 65 字节 {@code r‖s‖v}（v = 27/28，与 {@code eth_signTypedData} 返回一致）。
 *
 * <p>私钥通过 {@link SigningKey} 抽象传入——本地私钥 / AWS KMS / HSM 均可复用同一入口，
 * 与 {@link io.github.superedison.web3.chain.evm.message.EvmMessageSigner} 风格一致。
 */
public final class EvmTypedDataSigner {

    /** EVM 地址编解码：仅接受 EvmAddress、20 字节或 40 位十六进制地址。 */
    public static final AddressCodec EVM_ADDRESS_CODEC = value -> {
        if (value instanceof EvmAddress ea) {
            return ea.toBytes();
        }
        if (value instanceof String hex) {
            return parseHexAddress(hex);
        }
        if (value instanceof byte[] bytes) {
            return EvmAddress.fromBytes(bytes).toBytes();
        }
        throw new IllegalArgumentException(
                "Unsupported EVM address value: " + (value == null ? "null" : value.getClass()));
    };

    private static byte[] parseHexAddress(String value) {
        EvmAddress address = EvmAddress.fromHex(value);
        String hex = value.startsWith("0x") || value.startsWith("0X") ? value.substring(2) : value;

        boolean hasLower = false;
        boolean hasUpper = false;
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            hasLower |= c >= 'a' && c <= 'f';
            hasUpper |= c >= 'A' && c <= 'F';
        }
        if (hasLower && hasUpper && !Eip55Checksum.verify("0x" + hex)) {
            throw new AddressException("Invalid EIP-55 checksum: " + value);
        }
        return address.toBytes();
    }

    private EvmTypedDataSigner() {}

    /** 计算 EIP-712 32 字节签名摘要。 */
    public static byte[] hashTypedData(Eip712TypedData data) {
        return new Eip712Encoder(data, EVM_ADDRESS_CODEC).digest();
    }

    /** 计算域分隔符（domainSeparator），用于调试/交叉校验。 */
    public static byte[] domainSeparator(Eip712TypedData data) {
        return new Eip712Encoder(data, EVM_ADDRESS_CODEC).domainSeparator();
    }

    /** 签名结构化数据。 */
    public static Signature signTypedData(Eip712TypedData data, SigningKey signingKey) {
        return signHash(hashTypedData(data), signingKey);
    }

    /** 直接签 32 字节 EIP-712 摘要。 */
    public static Signature signHash(byte[] digest, SigningKey signingKey) {
        if (digest == null || digest.length != 32) {
            throw new IllegalArgumentException("Digest must be 32 bytes");
        }
        var sig = signingKey.sign(digest);
        if (!(sig instanceof Secp256k1Signer.Secp256k1Signature secpSig)) {
            throw new IllegalStateException("Unexpected signature type: " + sig.getClass());
        }
        return EvmSignature.fromRecoveryId(secpSig.r(), secpSig.s(), secpSig.v());
    }

    /** 验证结构化数据签名。 */
    public static boolean verifyTypedData(Eip712TypedData data, Signature signature, byte[] publicKey) {
        return verifyHash(hashTypedData(data), signature, publicKey);
    }

    /** 验证摘要签名。 */
    public static boolean verifyHash(byte[] digest, Signature signature, byte[] publicKey) {
        if (digest == null || digest.length != 32) {
            return false;
        }
        if (!(signature instanceof EvmSignature evmSig)) {
            return false;
        }
        try {
            Secp256k1SignatureValidator.requireCanonicalLegacyV(evmSig.bytes());
            return Secp256k1Signer.verify(digest, evmSig.getR(), evmSig.getS(), publicKey);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** 从结构化数据 + 65 字节签名反算签名者地址（ecrecover）。前端 MetaMask signTypedData 出来的 hex 直接传入。 */
    public static EvmAddress recoverAddress(Eip712TypedData data, byte[] signature) {
        Secp256k1SignatureValidator.requireCanonicalLegacyV(signature);
        return EvmAddress.recover(hashTypedData(data), signature);
    }

    /** {@link #recoverAddress(Eip712TypedData, byte[])} 的 Signature 重载。 */
    public static EvmAddress recoverAddress(Eip712TypedData data, Signature signature) {
        return recoverAddress(data, signature.bytes());
    }

    /** 判断签名是否由 {@code expected} 地址签出；验签失败/格式错误返回 false，不抛异常。 */
    public static boolean verifyTypedDataAddress(Eip712TypedData data, byte[] signature, EvmAddress expected) {
        if (expected == null) return false;
        try {
            return expected.equals(recoverAddress(data, signature));
        } catch (RuntimeException e) {
            return false;
        }
    }
}

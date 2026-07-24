package io.github.superedison.web3.chain.tron.tip712;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.chain.tron.internal.TronSignature;
import io.github.superedison.web3.chain.spi.signing.Secp256k1SignatureValidator;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.eip712.AddressCodec;
import io.github.superedison.web3.crypto.eip712.Eip712Encoder;
import io.github.superedison.web3.crypto.eip712.Eip712TypedData;

/**
 * TRON TIP-712 结构化数据签名器（对齐 tronweb {@code signTypedData} / {@code verifyTypedData}）。
 *
 * <p>复用 {@link Eip712Encoder}（与 EVM 共用一份编码逻辑），仅注入 TRON 地址编解码：
 * 支持 base58（{@code T...}）与 21 字节 0x41 前缀剥离；{@code trcToken} 由编码器按 uint256 处理。
 * 摘要 = {@code keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(message))}，
 * 再用 secp256k1 签出 65 字节 {@code r‖s‖v}（v = 27/28）。
 *
 * <p>chainId 使用 {@code block.chainid & 0xffffffff}：主网见 {@link #MAINNET_CHAIN_ID}，
 * Nile 测试网见 {@link #NILE_CHAIN_ID}。
 */
public final class TronTypedDataSigner {

    /** TRON 主网 chainId（block.chainid &amp; 0xffffffff）。 */
    public static final long MAINNET_CHAIN_ID = 0x2b6653dcL;
    /** TRON Nile 测试网 chainId（block.chainid &amp; 0xffffffff）。 */
    public static final long NILE_CHAIN_ID = 0xcd8690dcL;

    /** TRON 地址编解码：TronAddress / base58 T-地址剥 0x41，其余回落默认（0x-hex / 字节）。 */
    public static final AddressCodec TRON_ADDRESS_CODEC = value -> {
        if (value instanceof TronAddress ta) {
            return strip41(ta.toBytes());
        }
        if (value instanceof String s && s.startsWith("T")) {
            return strip41(TronAddress.fromBase58(s).toBytes());
        }
        return AddressCodec.DEFAULT.toAddress20(value);
    };

    private TronTypedDataSigner() {}

    private static byte[] strip41(byte[] full21) {
        byte[] body = new byte[20];
        System.arraycopy(full21, 1, body, 0, 20);
        return body;
    }

    /** 计算 TIP-712 32 字节签名摘要。 */
    public static byte[] hashTypedData(Eip712TypedData data) {
        return new Eip712Encoder(data, TRON_ADDRESS_CODEC).digest();
    }

    /** 计算域分隔符（domainSeparator），用于调试/交叉校验。 */
    public static byte[] domainSeparator(Eip712TypedData data) {
        return new Eip712Encoder(data, TRON_ADDRESS_CODEC).domainSeparator();
    }

    /** 签名结构化数据。 */
    public static Signature signTypedData(Eip712TypedData data, SigningKey signingKey) {
        return signHash(hashTypedData(data), signingKey);
    }

    /** 直接签 32 字节 TIP-712 摘要。 */
    public static Signature signHash(byte[] digest, SigningKey signingKey) {
        if (digest == null || digest.length != 32) {
            throw new IllegalArgumentException("Digest must be 32 bytes");
        }
        var sig = signingKey.sign(digest);
        if (!(sig instanceof Secp256k1Signer.Secp256k1Signature secpSig)) {
            throw new IllegalStateException("Unexpected signature type: " + sig.getClass());
        }
        return TronSignature.fromSecp256k1Signature(secpSig);
    }

    /** 验证结构化数据签名。 */
    public static boolean verifyTypedData(Eip712TypedData data, Signature signature, byte[] publicKey) {
        return verifyHash(hashTypedData(data), signature, publicKey);
    }

    /** 验证摘要签名。 */
    public static boolean verifyHash(byte[] digest, Signature signature, byte[] publicKey) {
        if (digest == null || digest.length != 32 || signature == null) {
            return false;
        }
        if (publicKey == null || (publicKey.length != 64 && publicKey.length != 65)) {
            return false;
        }
        try {
            byte[] sigBytes = signature.bytes();
            if (sigBytes == null || sigBytes.length != 65) {
                return false;
            }
            Secp256k1SignatureValidator.requireCanonicalLegacyV(sigBytes);
            TronSignature tronSig = TronSignature.fromCompact(sigBytes);
            return Secp256k1Signer.verify(digest, tronSig.getR(), tronSig.getS(), publicKey);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** 从结构化数据 + 65 字节签名反算签名者地址（ecrecover）。 */
    public static TronAddress recoverAddress(Eip712TypedData data, byte[] signature) {
        Secp256k1SignatureValidator.requireCanonicalLegacyV(signature);
        return TronAddress.recover(hashTypedData(data), signature);
    }

    /** {@link #recoverAddress(Eip712TypedData, byte[])} 的 Signature 重载。 */
    public static TronAddress recoverAddress(Eip712TypedData data, Signature signature) {
        return recoverAddress(data, signature.bytes());
    }

    /** 判断签名是否由 {@code expected} 地址签出；验签失败/格式错误返回 false，不抛异常。 */
    public static boolean verifyTypedDataAddress(Eip712TypedData data, byte[] signature, TronAddress expected) {
        if (expected == null) return false;
        try {
            return expected.equals(recoverAddress(data, signature));
        } catch (RuntimeException e) {
            return false;
        }
    }
}

package io.github.superedison.web3.crypto.ecc;

import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.util.SecureBytes;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Secp256k1 椭圆曲线签名器
 * 用于以太坊、比特币等链
 *
 * 安全注意事项：
 * - 私钥是"能力"，不是"数据"，不能被读取
 * - 使用完毕后必须调用 close() 或 destroy() 擦除私钥
 * - 推荐使用 try-with-resources 语法
 *
 * 示例：
 * <pre>{@code
 * try (Secp256k1Signer signer = new Secp256k1Signer(privateKey)) {
 *     Signature sig = signer.sign(messageHash);
 * } // 自动擦除私钥
 * }</pre>
 */
public class Secp256k1Signer implements SigningKey {

    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters CURVE = new ECDomainParameters(
            CURVE_PARAMS.getCurve(),
            CURVE_PARAMS.getG(),
            CURVE_PARAMS.getN(),
            CURVE_PARAMS.getH()
    );
    private static final BigInteger HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);

    private final byte[] privateKey;
    private final byte[] publicKey;
    private final byte[] compressedPublicKey;
    private volatile boolean destroyed = false;

    /**
     * 从私钥创建签名器
     * @param privateKey 32字节私钥
     */
    public Secp256k1Signer(byte[] privateKey) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }
        this.privateKey = SecureBytes.copy(privateKey);
        this.publicKey = derivePublicKey(privateKey, false);
        this.compressedPublicKey = derivePublicKey(privateKey, true);
    }

    /**
     * 从私钥派生公钥
     * @param privateKey 私钥
     * @param compressed 是否压缩
     * @return 公钥字节数组
     */
    public static byte[] derivePublicKey(byte[] privateKey, boolean compressed) {
        BigInteger privKey = new BigInteger(1, privateKey);
        ECPoint point = new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
        return point.getEncoded(compressed);
    }

    /**
     * 对消息哈希签名
     * @param messageHash 32字节消息哈希
     * @return 签名结果
     * @throws IllegalStateException 如果签名器已销毁
     */
    @Override
    public Signature sign(byte[] messageHash) {
        checkNotDestroyed();
        if (messageHash == null || messageHash.length != 32) {
            throw new IllegalArgumentException("Message hash must be 32 bytes");
        }

        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(
                new BigInteger(1, privateKey), CURVE);
        signer.init(true, privKeyParams);

        BigInteger[] signature = signer.generateSignature(messageHash);
        BigInteger r = signature[0];
        BigInteger s = signature[1];

        // 确保 s 是低阶值（EIP-2）
        if (s.compareTo(HALF_CURVE_ORDER) > 0) {
            s = CURVE.getN().subtract(s);
        }

        // 计算恢复 ID
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            byte[] recovered = recoverPublicKey(messageHash, r, s, i);
            if (recovered != null && Arrays.equals(recovered, publicKey)) {
                recId = i;
                break;
            }
        }

        if (recId == -1) {
            throw new RuntimeException("Could not calculate recovery id");
        }

        return new Secp256k1Signature(
                SecureBytes.padLeft(r.toByteArray(), 32),
                SecureBytes.padLeft(s.toByteArray(), 32),
                recId
        );
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("SigningKey has been destroyed");
        }
    }

    /**
     * 验证签名
     * @param messageHash 消息哈希
     * @param r 签名 r
     * @param s 签名 s
     * @param publicKey 公钥
     * @return 是否有效
     */
    public static boolean verify(byte[] messageHash, byte[] r, byte[] s, byte[] publicKey) {
        try {
            ECDSASigner signer = new ECDSASigner();
            ECPoint point = CURVE.getCurve().decodePoint(publicKey);
            ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(point, CURVE);
            signer.init(false, pubKeyParams);

            BigInteger rBigInt = new BigInteger(1, r);
            BigInteger sBigInt = new BigInteger(1, s);

            return signer.verifySignature(messageHash, rBigInt, sBigInt);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 从签名恢复公钥
     * @param messageHash 消息哈希
     * @param r 签名 r
     * @param s 签名 s
     * @param recId 恢复 ID (0-3)
     * @return 公钥字节数组，失败返回 null
     */
    public static byte[] recoverPublicKey(byte[] messageHash, byte[] r, byte[] s, int recId) {
        return recoverPublicKey(messageHash, new BigInteger(1, r), new BigInteger(1, s), recId);
    }

    /**
     * 从签名恢复公钥
     */
    public static byte[] recoverPublicKey(byte[] messageHash, BigInteger r, BigInteger s, int recId) {
        if (recId < 0 || recId > 3) {
            return null;
        }

        BigInteger n = CURVE.getN();
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));

        if (x.compareTo(CURVE_PARAMS.getCurve().getField().getCharacteristic()) >= 0) {
            return null;
        }

        ECPoint R = decompressPoint(x, (recId & 1) == 1);
        if (R == null || !R.multiply(n).isInfinity()) {
            return null;
        }

        BigInteger e = new BigInteger(1, messageHash);
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);

        ECPoint q = sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);
        return q.getEncoded(false);
    }

    private static ECPoint decompressPoint(BigInteger x, boolean yBit) {
        try {
            byte[] compEnc = new byte[33];
            compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
            byte[] xBytes = x.toByteArray();
            if (xBytes.length <= 32) {
                System.arraycopy(xBytes, 0, compEnc, 33 - xBytes.length, xBytes.length);
            } else {
                System.arraycopy(xBytes, xBytes.length - 32, compEnc, 1, 32);
            }
            return CURVE.getCurve().decodePoint(compEnc);
        } catch (Exception e) {
            return null;
        }
    }

    private static ECPoint sumOfTwoMultiplies(ECPoint P, BigInteger a, ECPoint Q, BigInteger b) {
        FixedPointCombMultiplier multiplier = new FixedPointCombMultiplier();
        ECPoint pA = multiplier.multiply(P, a);
        ECPoint qB = multiplier.multiply(Q, b);
        return pA.add(qB);
    }

    /**
     * 获取公钥（非压缩，65字节）
     */
    @Override
    public byte[] getPublicKey() {
        checkNotDestroyed();
        return SecureBytes.copy(publicKey);
    }

    /**
     * 获取压缩公钥（33字节）
     */
    public byte[] getCompressedPublicKey() {
        checkNotDestroyed();
        return SecureBytes.copy(compressedPublicKey);
    }

    /**
     * 获取签名算法类型
     */
    @Override
    public SignatureScheme getScheme() {
        return SignatureScheme.ECDSA_SECP256K1;
    }

    /**
     * 销毁私钥
     * 调用后私钥将被清零，SigningKey 不可再使用
     */
    @Override
    public void destroy() {
        if (!destroyed) {
            SecureBytes.secureWipe(privateKey);
            destroyed = true;
        }
    }

    /**
     * 是否已销毁
     */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    /**
     * 安全的 toString 实现，不暴露私钥
     */
    @Override
    public String toString() {
        return "Secp256k1Signer{***REDACTED***}";
    }

    /**
     * Secp256k1 签名结果，实现通用 Signature 接口
     */
    public record Secp256k1Signature(byte[] r, byte[] s, int v) implements Signature {

        /**
         * 获取签名字节（紧凑格式，65字节: r + s + v）
         */
        @Override
        public byte[] bytes() {
            return toCompact();
        }

        /**
         * 获取签名算法
         */
        @Override
        public SignatureScheme scheme() {
            return SignatureScheme.ECDSA_SECP256K1;
        }

        /**
         * 转为紧凑格式（65字节: r + s + v）
         */
        public byte[] toCompact() {
            byte[] result = new byte[65];
            System.arraycopy(r, 0, result, 0, 32);
            System.arraycopy(s, 0, result, 32, 32);
            result[64] = (byte) v;
            return result;
        }

        /**
         * 转为以太坊格式的 v 值
         */
        public int getEthereumV() {
            return v + 27;
        }

        /**
         * 转为 EIP-155 格式的 v 值
         */
        public int getEip155V(long chainId) {
            return (int) (v + chainId * 2 + 35);
        }
    }
}
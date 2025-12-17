package io.github.superedison.web3.chain.btc.address;

import io.github.superedison.web3.chain.exception.AddressException;
import io.github.superedison.web3.crypto.hash.Sha256;

import java.util.Arrays;

/**
 * Bitcoin Taproot 地址 (P2TR)
 *
 * 使用 Bech32m 编码，witness version 1
 * 主网地址以 'bc1p' 开头
 *
 * BIP-86 路径: m/86'/0'/0'/0/0
 *
 * Taproot 公钥是 x-only 公钥（32 字节），去除了 y 坐标的前缀
 */
public final class TaprootAddress extends BtcAddress {

    private static final int PROGRAM_LENGTH = 32;
    private static final int WITNESS_VERSION = 1;

    private TaprootAddress(byte[] outputKey, BtcNetwork network) {
        super(outputKey, network, BtcAddressType.P2TR);
    }

    /**
     * 从公钥创建 Taproot 地址
     *
     * 对于简单的 key-path spending，使用 BIP-86:
     * 1. 取 x-only 公钥（去除前缀的 32 字节）
     * 2. 计算 tweaked public key
     *
     * @param publicKey 33 字节压缩公钥或 65 字节未压缩公钥
     */
    public static TaprootAddress fromPublicKey(byte[] publicKey, BtcNetwork network) {
        if (publicKey == null) {
            throw new AddressException("Public key cannot be null");
        }

        // 获取 x-only 公钥
        byte[] xOnlyPubKey = toXOnlyPublicKey(publicKey);

        // 计算 taproot output key (BIP-86 key-path only)
        byte[] outputKey = computeTaprootOutputKey(xOnlyPubKey);

        return new TaprootAddress(outputKey, network);
    }

    /**
     * 从 x-only 公钥创建地址（不进行 tweak）
     * 仅用于直接使用 output key 的场景
     */
    public static TaprootAddress fromXOnlyPublicKey(byte[] xOnlyPubKey, BtcNetwork network) {
        if (xOnlyPubKey == null || xOnlyPubKey.length != PROGRAM_LENGTH) {
            throw new AddressException("X-only public key must be 32 bytes");
        }
        return new TaprootAddress(xOnlyPubKey, network);
    }

    /**
     * 从 tweaked output key 创建地址
     */
    public static TaprootAddress fromOutputKey(byte[] outputKey, BtcNetwork network) {
        if (outputKey == null || outputKey.length != PROGRAM_LENGTH) {
            throw new AddressException("Taproot output key must be 32 bytes");
        }
        return new TaprootAddress(outputKey, network);
    }

    /**
     * 从 Bech32m 编码的地址字符串解析
     */
    public static TaprootAddress fromBech32(String address) {
        if (address == null || address.isEmpty()) {
            throw AddressException.invalidFormat(address);
        }

        try {
            // 确定网络
            BtcNetwork network;
            String hrp;
            if (address.toLowerCase().startsWith("bc1p")) {
                network = BtcNetwork.MAINNET;
                hrp = "bc";
            } else if (address.toLowerCase().startsWith("tb1p")) {
                network = BtcNetwork.TESTNET;
                hrp = "tb";
            } else if (address.toLowerCase().startsWith("bcrt1p")) {
                network = BtcNetwork.REGTEST;
                hrp = "bcrt";
            } else {
                throw AddressException.invalidFormat(address);
            }

            Bech32.DecodedSegWitAddress decoded = Bech32.decodeSegWitAddress(hrp, address);

            if (decoded.witnessVersion() != WITNESS_VERSION) {
                throw new AddressException("Expected witness version 1, got " + decoded.witnessVersion());
            }

            if (decoded.witnessProgram().length != PROGRAM_LENGTH) {
                throw new AddressException("Taproot witness program must be 32 bytes");
            }

            return new TaprootAddress(decoded.witnessProgram(), network);
        } catch (IllegalArgumentException e) {
            throw new AddressException("Invalid Taproot address: " + address, e);
        }
    }

    /**
     * 验证 Taproot 地址格式
     */
    public static boolean isValid(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        String lower = address.toLowerCase();
        if (!lower.startsWith("bc1p") && !lower.startsWith("tb1p") && !lower.startsWith("bcrt1p")) {
            return false;
        }
        try {
            fromBech32(address);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 获取 witness version
     */
    public int getWitnessVersion() {
        return WITNESS_VERSION;
    }

    /**
     * 获取 taproot output key (witness program)
     */
    public byte[] getOutputKey() {
        return getHash();
    }

    @Override
    public String toBase58() {
        // Taproot 使用 Bech32m，不是 Base58
        return toBech32m();
    }

    /**
     * 获取 Bech32m 编码的地址
     */
    public String toBech32m() {
        return Bech32.encodeSegWitAddress(network.getBech32Hrp(), WITNESS_VERSION, hash);
    }

    /**
     * 获取脚本公钥（ScriptPubKey）
     * OP_1 <32 bytes output key>
     */
    public byte[] getScriptPubKey() {
        byte[] script = new byte[34];
        script[0] = 0x51; // OP_1 (witness version 1)
        script[1] = 0x20; // Push 32 bytes
        System.arraycopy(hash, 0, script, 2, 32);
        return script;
    }

    /**
     * 将公钥转换为 x-only 格式（32 字节）
     */
    private static byte[] toXOnlyPublicKey(byte[] publicKey) {
        if (publicKey.length == 32) {
            return publicKey;
        }
        if (publicKey.length == 33) {
            // 压缩公钥，去除前缀
            return Arrays.copyOfRange(publicKey, 1, 33);
        }
        if (publicKey.length == 65 && publicKey[0] == 0x04) {
            // 未压缩公钥，取 x 坐标
            return Arrays.copyOfRange(publicKey, 1, 33);
        }
        throw new AddressException("Invalid public key length: " + publicKey.length);
    }

    /**
     * 计算 BIP-86 tweaked public key
     *
     * BIP-86 使用空的 merkle root，所以 tweak = tagged_hash("TapTweak", pubkey)
     * output_key = pubkey + tweak * G
     *
     * 简化实现：对于 key-path only spending，直接使用 x-only 公钥
     * 完整实现需要椭圆曲线点加法
     */
    private static byte[] computeTaprootOutputKey(byte[] xOnlyPubKey) {
        // BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
        byte[] tagHash = Sha256.hash("TapTweak".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] preimage = new byte[tagHash.length * 2 + xOnlyPubKey.length];
        System.arraycopy(tagHash, 0, preimage, 0, tagHash.length);
        System.arraycopy(tagHash, 0, preimage, tagHash.length, tagHash.length);
        System.arraycopy(xOnlyPubKey, 0, preimage, tagHash.length * 2, xOnlyPubKey.length);

        byte[] tweak = Sha256.hash(preimage);

        // 完整实现需要：output_key = lift_x(pubkey) + tweak * G
        // 这里使用简化版本：对于 key-path only，直接返回 tweaked key
        // 实际应用中应该使用 secp256k1 库进行点运算

        // 简化：返回 tagged hash 作为 output key
        // 这仅用于演示，生产环境应使用完整的 BIP-340/BIP-341 实现
        return computeTweakedPublicKey(xOnlyPubKey, tweak);
    }

    /**
     * 计算 tweaked public key
     * P + t*G where t = tagged_hash("TapTweak", P)
     */
    private static byte[] computeTweakedPublicKey(byte[] xOnlyPubKey, byte[] tweak) {
        try {
            // 使用 BouncyCastle 进行椭圆曲线运算
            org.bouncycastle.asn1.x9.X9ECParameters curveParams =
                    org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("secp256k1");
            org.bouncycastle.math.ec.ECPoint G = curveParams.getG();
            org.bouncycastle.math.ec.ECCurve curve = curveParams.getCurve();

            // 从 x-only 公钥恢复点（假设 y 坐标为偶数）
            java.math.BigInteger x = new java.math.BigInteger(1, xOnlyPubKey);
            org.bouncycastle.math.ec.ECPoint P = liftX(curve, x);

            if (P == null) {
                // 如果无法恢复点，返回原始公钥
                return xOnlyPubKey;
            }

            // 计算 t * G
            java.math.BigInteger t = new java.math.BigInteger(1, tweak);
            t = t.mod(curveParams.getN()); // 确保 t 在有效范围内
            org.bouncycastle.math.ec.ECPoint tG = G.multiply(t);

            // 计算 P + t*G
            org.bouncycastle.math.ec.ECPoint Q = P.add(tG).normalize();

            // 返回 x-only 格式
            byte[] qx = Q.getAffineXCoord().getEncoded();
            if (qx.length == 32) {
                return qx;
            }
            // 确保是 32 字节
            byte[] result = new byte[32];
            if (qx.length > 32) {
                System.arraycopy(qx, qx.length - 32, result, 0, 32);
            } else {
                System.arraycopy(qx, 0, result, 32 - qx.length, qx.length);
            }
            return result;

        } catch (Exception e) {
            // 如果椭圆曲线运算失败，返回原始公钥
            return xOnlyPubKey;
        }
    }

    /**
     * BIP-340 lift_x: 从 x 坐标恢复椭圆曲线点
     */
    private static org.bouncycastle.math.ec.ECPoint liftX(
            org.bouncycastle.math.ec.ECCurve curve, java.math.BigInteger x) {
        try {
            // y^2 = x^3 + 7 (mod p) for secp256k1
            java.math.BigInteger p = curve.getField().getCharacteristic();
            java.math.BigInteger y2 = x.pow(3).add(java.math.BigInteger.valueOf(7)).mod(p);

            // 计算平方根
            java.math.BigInteger y = modSqrt(y2, p);
            if (y == null) {
                return null;
            }

            // 选择偶数 y
            if (y.testBit(0)) {
                y = p.subtract(y);
            }

            return curve.createPoint(x, y);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 模平方根（Tonelli-Shanks 简化版，适用于 p ≡ 3 (mod 4)）
     */
    private static java.math.BigInteger modSqrt(java.math.BigInteger a, java.math.BigInteger p) {
        // 对于 secp256k1，p ≡ 3 (mod 4)
        // sqrt(a) = a^((p+1)/4) mod p
        java.math.BigInteger exp = p.add(java.math.BigInteger.ONE).divide(java.math.BigInteger.valueOf(4));
        java.math.BigInteger result = a.modPow(exp, p);

        // 验证
        if (result.modPow(java.math.BigInteger.TWO, p).equals(a.mod(p))) {
            return result;
        }
        return null;
    }

    @Override
    public String toString() {
        return toBech32m();
    }
}

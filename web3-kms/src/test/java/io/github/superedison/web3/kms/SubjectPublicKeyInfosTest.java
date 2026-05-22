package io.github.superedison.web3.kms;

import io.github.superedison.web3.crypto.ecc.Ed25519Signer;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SubjectPublicKeyInfos - X.509 SubjectPublicKeyInfo 解析")
class SubjectPublicKeyInfosTest {

    private static final ASN1ObjectIdentifier OID_ED25519 = new ASN1ObjectIdentifier("1.3.101.112");

    private static byte[] randomPrivKey() {
        byte[] sk = new byte[32];
        new SecureRandom().nextBytes(sk);
        sk[0] &= 0x7F;       // 避免 secp256k1 私钥 >= N
        if (sk[31] == 0) sk[31] = 1;
        return sk;
    }

    @Test
    @DisplayName("解析 secp256k1 SPKI → 65 字节非压缩公钥")
    void parsesSecp256k1Spki() throws Exception {
        byte[] sk = randomPrivKey();
        byte[] uncompressed = Secp256k1Signer.derivePublicKey(sk, false);  // 65 bytes, 04||X||Y

        AlgorithmIdentifier algo = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey,
                SECObjectIdentifiers.secp256k1
        );
        byte[] spkiDer = new SubjectPublicKeyInfo(algo, uncompressed).getEncoded();

        byte[] parsed = SubjectPublicKeyInfos.parseSecp256k1Uncompressed(spkiDer);

        assertThat(parsed).hasSize(65);
        assertThat(parsed[0]).isEqualTo((byte) 0x04);
        assertThat(parsed).isEqualTo(uncompressed);
    }

    @Test
    @DisplayName("KMS 若返回压缩公钥，也能解码并输出非压缩 65 字节")
    void normalizesCompressedToUncompressed() throws Exception {
        byte[] sk = randomPrivKey();
        byte[] uncompressed = Secp256k1Signer.derivePublicKey(sk, false);
        byte[] compressed = Secp256k1Signer.derivePublicKey(sk, true);    // 33 bytes

        AlgorithmIdentifier algo = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey,
                SECObjectIdentifiers.secp256k1
        );
        byte[] spkiDer = new SubjectPublicKeyInfo(algo, compressed).getEncoded();

        byte[] parsed = SubjectPublicKeyInfos.parseSecp256k1Uncompressed(spkiDer);

        assertThat(parsed).hasSize(65).isEqualTo(uncompressed);
    }

    @Test
    @DisplayName("曲线不是 secp256k1 时拒绝")
    void rejectsNonSecp256k1Curve() throws Exception {
        byte[] sk = randomPrivKey();
        byte[] uncompressed = Secp256k1Signer.derivePublicKey(sk, false);

        // 故意伪造算法 OID 为 secp256r1
        AlgorithmIdentifier wrongAlgo = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey,
                SECObjectIdentifiers.secp256r1
        );
        byte[] spkiDer = new SubjectPublicKeyInfo(wrongAlgo, uncompressed).getEncoded();

        assertThatThrownBy(() -> SubjectPublicKeyInfos.parseSecp256k1Uncompressed(spkiDer))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("secp256k1");
    }

    @Test
    @DisplayName("解析 Ed25519 SPKI → 32 字节原始公钥")
    void parsesEd25519Spki() throws Exception {
        byte[] sk = randomPrivKey();
        byte[] pub = Ed25519Signer.derivePublicKey(sk);  // 32 bytes raw

        AlgorithmIdentifier algo = new AlgorithmIdentifier(OID_ED25519);
        byte[] spkiDer = new SubjectPublicKeyInfo(algo, pub).getEncoded();

        byte[] parsed = SubjectPublicKeyInfos.parseEd25519(spkiDer);

        assertThat(parsed).hasSize(32).isEqualTo(pub);
    }

    @Test
    @DisplayName("Ed25519 OID 不匹配时拒绝")
    void rejectsNonEd25519Algorithm() throws Exception {
        byte[] sk = randomPrivKey();
        byte[] uncompressed = Secp256k1Signer.derivePublicKey(sk, false);

        AlgorithmIdentifier wrongAlgo = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey,
                SECObjectIdentifiers.secp256k1
        );
        byte[] spkiDer = new SubjectPublicKeyInfo(wrongAlgo, uncompressed).getEncoded();

        assertThatThrownBy(() -> SubjectPublicKeyInfos.parseEd25519(spkiDer))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Ed25519");
    }
}

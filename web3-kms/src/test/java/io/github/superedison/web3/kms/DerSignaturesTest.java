package io.github.superedison.web3.kms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DerSignatures - DER ECDSA 签名解析与 low-S 规范化")
class DerSignaturesTest {

    private static final BigInteger N = CustomNamedCurves.getByName("secp256k1").getN();
    private static final BigInteger HALF_N = N.shiftRight(1);

    private static byte[] encodeDer(BigInteger r, BigInteger s) throws Exception {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded();
    }

    @Test
    @DisplayName("可正确解析 KMS 风格 DER 签名为 (r, s)")
    void parsesValidDerSignature() throws Exception {
        BigInteger r = new BigInteger("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF", 16);
        BigInteger s = new BigInteger("FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321", 16);
        byte[] der = encodeDer(r, s);

        DerSignatures.RS rs = DerSignatures.parse(der);

        assertThat(rs.r()).isEqualTo(r);
        assertThat(rs.s()).isEqualTo(s);
    }

    @Test
    @DisplayName("空 / null DER 被拒绝")
    void rejectsEmptyDer() {
        assertThatThrownBy(() -> DerSignatures.parse(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> DerSignatures.parse(new byte[0]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("高-S 被归一化到低-S（EIP-2 / BIP-66）")
    void normalizesHighSToLowS() {
        BigInteger highS = N.subtract(BigInteger.ONE);  // > N/2
        BigInteger normalized = DerSignatures.normalizeLowS(highS);

        assertThat(normalized).isEqualTo(BigInteger.ONE);
        assertThat(normalized).isLessThanOrEqualTo(HALF_N);
    }

    @Test
    @DisplayName("低-S 保持不变")
    void leavesLowSUnchanged() {
        BigInteger lowS = HALF_N.subtract(BigInteger.ONE);
        assertThat(DerSignatures.normalizeLowS(lowS)).isEqualTo(lowS);
    }

    @Test
    @DisplayName("toFixed32: 小值左零填充到 32 字节")
    void padsSmallValueTo32Bytes() {
        byte[] out = DerSignatures.toFixed32(BigInteger.valueOf(1));
        assertThat(out).hasSize(32);
        assertThat(out[31]).isEqualTo((byte) 1);
        for (int i = 0; i < 31; i++) {
            assertThat(out[i]).isEqualTo((byte) 0);
        }
    }

    @Test
    @DisplayName("toFixed32: 33 字节带符号位 BigInteger 去掉首字节")
    void stripsBigIntegerSignByte() {
        // 第一位为 1 的 32 字节，BigInteger 会前置一个 0x00 符号字节变成 33 字节
        byte[] raw = new byte[32];
        raw[0] = (byte) 0xFF;
        BigInteger value = new BigInteger(1, raw);

        byte[] out = DerSignatures.toFixed32(value);

        assertThat(out).hasSize(32);
        assertThat(out[0]).isEqualTo((byte) 0xFF);
    }
}

package io.github.superedison.web3.chain.evm.internal;

import io.github.superedison.web3.core.signer.SignatureScheme;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;

/**
 * EvmSignature 单元测试
 * 测试 EVM 签名的格式转换
 */
@DisplayName("EvmSignature EVM签名测试")
class EvmSignatureTest {

    @Nested
    @DisplayName("fromRecoveryId 方法测试")
    class FromRecoveryIdTest {

        @Test
        @DisplayName("recoveryId=0 应该转换为 v=27")
        void recoveryId0ToV27() {
            byte[] r = new byte[32];
            byte[] s = new byte[32];
            Arrays.fill(r, (byte) 0x01);
            Arrays.fill(s, (byte) 0x02);

            EvmSignature sig = EvmSignature.fromRecoveryId(r, s, 0);

            assertThat(sig.getV()).isEqualTo(27);
            assertThat(sig.getRecoveryId()).isEqualTo(0);
        }

        @Test
        @DisplayName("recoveryId=1 应该转换为 v=28")
        void recoveryId1ToV28() {
            byte[] r = new byte[32];
            byte[] s = new byte[32];

            EvmSignature sig = EvmSignature.fromRecoveryId(r, s, 1);

            assertThat(sig.getV()).isEqualTo(28);
            assertThat(sig.getRecoveryId()).isEqualTo(1);
        }

        @Test
        @DisplayName("短 r 值应该被左填充到32字节")
        void shortRIsPadded() {
            byte[] shortR = new byte[]{0x01, 0x02, 0x03};
            byte[] s = new byte[32];

            EvmSignature sig = EvmSignature.fromRecoveryId(shortR, s, 0);

            assertThat(sig.getR()).hasSize(32);
            // 前29字节应该是0
            byte[] expected = new byte[32];
            expected[29] = 0x01;
            expected[30] = 0x02;
            expected[31] = 0x03;
            assertThat(sig.getR()).isEqualTo(expected);
        }

        @Test
        @DisplayName("短 s 值应该被左填充到32字节")
        void shortSIsPadded() {
            byte[] r = new byte[32];
            byte[] shortS = new byte[]{0x04, 0x05};

            EvmSignature sig = EvmSignature.fromRecoveryId(r, shortS, 0);

            assertThat(sig.getS()).hasSize(32);
        }
    }

    @Nested
    @DisplayName("fromCompact 方法测试")
    class FromCompactTest {

        @Test
        @DisplayName("65字节紧凑格式应该正确解析")
        void parseCompactFormat() {
            byte[] compact = new byte[65];
            // 填充 r
            for (int i = 0; i < 32; i++) compact[i] = (byte) (i + 1);
            // 填充 s
            for (int i = 32; i < 64; i++) compact[i] = (byte) (i + 1);
            // v
            compact[64] = 27;

            EvmSignature sig = EvmSignature.fromCompact(compact);

            assertThat(sig.getR()).hasSize(32);
            assertThat(sig.getS()).hasSize(32);
            assertThat(sig.getV()).isEqualTo(27);
        }

        @Test
        @DisplayName("非65字节应该抛出异常")
        void invalidLengthThrows() {
            assertThatThrownBy(() -> EvmSignature.fromCompact(new byte[64]))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("65 bytes");

            assertThatThrownBy(() -> EvmSignature.fromCompact(new byte[66]))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("bytes 方法测试")
    class BytesTest {

        @Test
        @DisplayName("应该返回65字节紧凑格式")
        void returns65Bytes() {
            byte[] r = new byte[32];
            byte[] s = new byte[32];
            Arrays.fill(r, (byte) 0xAA);
            Arrays.fill(s, (byte) 0xBB);

            EvmSignature sig = EvmSignature.fromRecoveryId(r, s, 0);
            byte[] bytes = sig.bytes();

            assertThat(bytes).hasSize(65);
            assertThat(Arrays.copyOfRange(bytes, 0, 32)).isEqualTo(r);
            assertThat(Arrays.copyOfRange(bytes, 32, 64)).isEqualTo(s);
            assertThat(bytes[64]).isEqualTo((byte) 27);
        }
    }

    @Nested
    @DisplayName("scheme 方法测试")
    class SchemeTest {

        @Test
        @DisplayName("应该返回 ECDSA_SECP256K1")
        void returnsEcdsaSecp256k1() {
            EvmSignature sig = EvmSignature.fromRecoveryId(new byte[32], new byte[32], 0);

            assertThat(sig.scheme()).isEqualTo(SignatureScheme.ECDSA_SECP256K1);
        }
    }

    @Nested
    @DisplayName("Getter 方法测试")
    class GetterTest {

        @Test
        @DisplayName("getR 应该返回副本")
        void getRReturnsCopy() {
            byte[] r = new byte[32];
            Arrays.fill(r, (byte) 0x11);
            EvmSignature sig = EvmSignature.fromRecoveryId(r, new byte[32], 0);

            byte[] r1 = sig.getR();
            byte[] r2 = sig.getR();

            r1[0] = (byte) 0xFF;
            assertThat(r2[0]).isNotEqualTo((byte) 0xFF);
        }

        @Test
        @DisplayName("getS 应该返回副本")
        void getSReturnsCopy() {
            byte[] s = new byte[32];
            Arrays.fill(s, (byte) 0x22);
            EvmSignature sig = EvmSignature.fromRecoveryId(new byte[32], s, 0);

            byte[] s1 = sig.getS();
            byte[] s2 = sig.getS();

            s1[0] = (byte) 0xFF;
            assertThat(s2[0]).isNotEqualTo((byte) 0xFF);
        }

        @Test
        @DisplayName("getRBigInt 应该返回正确的 BigInteger")
        void getRBigIntCorrect() {
            byte[] r = new byte[32];
            r[31] = 0x01; // r = 1
            EvmSignature sig = EvmSignature.fromRecoveryId(r, new byte[32], 0);

            assertThat(sig.getRBigInt()).isEqualTo(BigInteger.ONE);
        }

        @Test
        @DisplayName("getSBigInt 应该返回正确的 BigInteger")
        void getSBigIntCorrect() {
            byte[] s = new byte[32];
            s[30] = 0x01;
            s[31] = 0x00; // s = 256
            EvmSignature sig = EvmSignature.fromRecoveryId(new byte[32], s, 0);

            assertThat(sig.getSBigInt()).isEqualTo(BigInteger.valueOf(256));
        }
    }

    @Nested
    @DisplayName("getRecoveryId 方法测试")
    class GetRecoveryIdTest {

        @Test
        @DisplayName("v=27 应该返回 recoveryId=0")
        void v27ReturnsRecoveryId0() {
            EvmSignature sig = EvmSignature.fromRecoveryId(new byte[32], new byte[32], 0);

            assertThat(sig.getRecoveryId()).isEqualTo(0);
        }

        @Test
        @DisplayName("v=28 应该返回 recoveryId=1")
        void v28ReturnsRecoveryId1() {
            EvmSignature sig = EvmSignature.fromRecoveryId(new byte[32], new byte[32], 1);

            assertThat(sig.getRecoveryId()).isEqualTo(1);
        }

        @Test
        @DisplayName("EIP-155 v 值应该正确计算 recoveryId")
        void eip155VCalculatesRecoveryId() {
            // EIP-155: v = chainId * 2 + 35 + recoveryId
            // 对于 chainId=1, recoveryId=0: v = 1*2 + 35 + 0 = 37
            // 对于 chainId=1, recoveryId=1: v = 1*2 + 35 + 1 = 38

            EvmSignature sig0 = EvmSignature.fromRecoveryId(new byte[32], new byte[32], 0)
                    .toEip155(1);
            assertThat(sig0.getV()).isEqualTo(37);
            assertThat(sig0.getRecoveryId()).isEqualTo(0);

            EvmSignature sig1 = EvmSignature.fromRecoveryId(new byte[32], new byte[32], 1)
                    .toEip155(1);
            assertThat(sig1.getV()).isEqualTo(38);
            assertThat(sig1.getRecoveryId()).isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("toEip155 方法测试")
    class ToEip155Test {

        @Test
        @DisplayName("Ethereum Mainnet (chainId=1) 转换")
        void ethereumMainnet() {
            EvmSignature sig = EvmSignature.fromRecoveryId(new byte[32], new byte[32], 0);

            EvmSignature eip155 = sig.toEip155(1);

            // v = chainId * 2 + 35 + recoveryId = 1 * 2 + 35 + 0 = 37
            assertThat(eip155.getV()).isEqualTo(37);
        }

        @Test
        @DisplayName("BSC (chainId=56) 转换")
        void bsc() {
            EvmSignature sig = EvmSignature.fromRecoveryId(new byte[32], new byte[32], 0);

            EvmSignature eip155 = sig.toEip155(56);

            // v = 56 * 2 + 35 + 0 = 147
            assertThat(eip155.getV()).isEqualTo(147);
        }

        @Test
        @DisplayName("Polygon (chainId=137) 转换")
        void polygon() {
            EvmSignature sig = EvmSignature.fromRecoveryId(new byte[32], new byte[32], 1);

            EvmSignature eip155 = sig.toEip155(137);

            // v = 137 * 2 + 35 + 1 = 310
            assertThat(eip155.getV()).isEqualTo(310);
        }

        @Test
        @DisplayName("toEip155 不应该修改原签名")
        void toEip155DoesNotModifyOriginal() {
            EvmSignature original = EvmSignature.fromRecoveryId(new byte[32], new byte[32], 0);
            int originalV = original.getV();

            EvmSignature eip155 = original.toEip155(1);

            assertThat(original.getV()).isEqualTo(originalV);
            assertThat(eip155.getV()).isNotEqualTo(originalV);
        }

        @Test
        @DisplayName("r 和 s 在转换后应该保持不变")
        void rAndSUnchangedAfterConversion() {
            byte[] r = new byte[32];
            byte[] s = new byte[32];
            Arrays.fill(r, (byte) 0xAA);
            Arrays.fill(s, (byte) 0xBB);

            EvmSignature original = EvmSignature.fromRecoveryId(r, s, 0);
            EvmSignature eip155 = original.toEip155(1);

            assertThat(eip155.getR()).isEqualTo(original.getR());
            assertThat(eip155.getS()).isEqualTo(original.getS());
        }
    }

    @Nested
    @DisplayName("padTo32 边界测试")
    class PadTo32Test {

        @Test
        @DisplayName("32字节应该原样返回")
        void exactly32BytesUnchanged() {
            byte[] r = new byte[32];
            Arrays.fill(r, (byte) 0xFF);
            EvmSignature sig = EvmSignature.fromRecoveryId(r, new byte[32], 0);

            assertThat(sig.getR()).isEqualTo(r);
        }

        @Test
        @DisplayName("超过32字节应该取最后32字节")
        void longerThan32BytesTruncated() {
            byte[] longR = new byte[33];
            longR[0] = 0x00; // 前导零（BigInteger 可能添加）
            Arrays.fill(longR, 1, 33, (byte) 0xAA);

            EvmSignature sig = EvmSignature.fromRecoveryId(longR, new byte[32], 0);

            byte[] expected = new byte[32];
            Arrays.fill(expected, (byte) 0xAA);
            assertThat(sig.getR()).isEqualTo(expected);
        }
    }
}
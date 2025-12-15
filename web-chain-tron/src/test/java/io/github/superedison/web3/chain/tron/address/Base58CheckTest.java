package io.github.superedison.web3.chain.tron.address;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Base58Check 编码/解码测试")
class Base58CheckTest {

    @Nested
    @DisplayName("encode 方法")
    class EncodeTest {

        @Test
        @DisplayName("编码空数组返回空字符串")
        void encodeEmptyReturnsEmpty() {
            String result = Base58Check.encode(new byte[0]);
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("编码单字节")
        void encodeSingleByte() {
            String result = Base58Check.encode(new byte[]{0x00});
            assertThat(result).isEqualTo("1");
        }

        @Test
        @DisplayName("编码多个前导零")
        void encodeLeadingZeros() {
            String result = Base58Check.encode(new byte[]{0x00, 0x00, 0x01});
            assertThat(result).startsWith("11");
        }

        @Test
        @DisplayName("编码已知测试向量")
        void encodeKnownVector() {
            byte[] input = hexToBytes("0488ade4");
            String result = Base58Check.encode(input);
            assertThat(result).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("decode 方法")
    class DecodeTest {

        @Test
        @DisplayName("解码空字符串返回空数组")
        void decodeEmptyReturnsEmpty() {
            byte[] result = Base58Check.decode("");
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("解码单个 '1' 返回单个零字节")
        void decodeSingleOne() {
            byte[] result = Base58Check.decode("1");
            assertThat(result).containsExactly(0x00);
        }

        @Test
        @DisplayName("无效字符抛出异常")
        void invalidCharacterThrows() {
            assertThatThrownBy(() -> Base58Check.decode("0OIl"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("encodeChecked/decodeChecked 方法")
    class CheckedTest {

        @Test
        @DisplayName("编码和解码互逆")
        void encodeDecodeRoundTrip() {
            byte[] original = new byte[]{0x41, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14};
            String encoded = Base58Check.encodeChecked(original);
            byte[] decoded = Base58Check.decodeChecked(encoded);
            assertThat(decoded).isEqualTo(original);
        }

        @Test
        @DisplayName("TRON 地址编码以 T 开头")
        void tronAddressStartsWithT() {
            byte[] tronAddress = new byte[21];
            tronAddress[0] = 0x41; // TRON 主网前缀
            String encoded = Base58Check.encodeChecked(tronAddress);
            assertThat(encoded).startsWith("T");
        }

        @Test
        @DisplayName("无效校验和抛出异常")
        void invalidChecksumThrows() {
            // 构造一个有效的 Base58 但校验和错误的字符串
            assertThatThrownBy(() -> Base58Check.decodeChecked("T111111111111111111111111111111111"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("checksum");
        }

        @Test
        @DisplayName("输入太短抛出异常")
        void tooShortThrows() {
            assertThatThrownBy(() -> Base58Check.decodeChecked("1"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("已知 TRON 地址测试向量")
    class TronAddressVectorTest {

        @Test
        @DisplayName("解码已知 TRON 地址")
        void decodeKnownTronAddress() {
            // 私钥 1 对应的 TRON 地址
            String address = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC";
            byte[] decoded = Base58Check.decodeChecked(address);

            assertThat(decoded).hasSize(21);
            assertThat(decoded[0]).isEqualTo((byte) 0x41);
        }
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}

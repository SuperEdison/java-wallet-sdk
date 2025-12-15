package io.github.superedison.web3.chain.tron.address;

import io.github.superedison.web3.chain.exception.AddressException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TronAddress TRON 地址测试")
class TronAddressTest {

    // 测试私钥：0x0000...0001 对应的 TRON 地址
    // 公钥 Keccak256 哈希后取后 20 字节，加 0x41 前缀
    private static final String KNOWN_ADDRESS = "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC";
    private static final String KNOWN_ADDRESS_HEX = "417e5f4552091a69125d5dfcb7b8c2659029395bdf";

    @Nested
    @DisplayName("fromBytes 方法")
    class FromBytesTest {

        @Test
        @DisplayName("21 字节创建成功")
        void validBytesCreateAddress() {
            byte[] bytes = hexToBytes(KNOWN_ADDRESS_HEX);
            TronAddress address = TronAddress.fromBytes(bytes);

            assertThat(address).isNotNull();
            assertThat(address.toBytes()).hasSize(21);
            assertThat(address.toBytes()[0]).isEqualTo((byte) 0x41);
        }

        @Test
        @DisplayName("空值抛出异常")
        void nullThrowsException() {
            assertThatThrownBy(() -> TronAddress.fromBytes(null))
                    .isInstanceOf(AddressException.class);
        }

        @Test
        @DisplayName("长度不对抛出异常")
        void wrongLengthThrowsException() {
            assertThatThrownBy(() -> TronAddress.fromBytes(new byte[20]))
                    .isInstanceOf(AddressException.class);
        }

        @Test
        @DisplayName("前缀不对抛出异常")
        void wrongPrefixThrowsException() {
            byte[] bytes = new byte[21];
            bytes[0] = 0x42; // 错误前缀
            assertThatThrownBy(() -> TronAddress.fromBytes(bytes))
                    .isInstanceOf(AddressException.class);
        }
    }

    @Nested
    @DisplayName("fromBase58 方法")
    class FromBase58Test {

        @Test
        @DisplayName("解析已知地址")
        void parseKnownAddress() {
            TronAddress address = TronAddress.fromBase58(KNOWN_ADDRESS);

            assertThat(address).isNotNull();
            assertThat(address.toBase58()).isEqualTo(KNOWN_ADDRESS);
        }

        @Test
        @DisplayName("空值抛出异常")
        void nullThrowsException() {
            assertThatThrownBy(() -> TronAddress.fromBase58(null))
                    .isInstanceOf(AddressException.class);
        }

        @Test
        @DisplayName("空字符串抛出异常")
        void emptyThrowsException() {
            assertThatThrownBy(() -> TronAddress.fromBase58(""))
                    .isInstanceOf(AddressException.class);
        }

        @Test
        @DisplayName("无效格式抛出异常")
        void invalidFormatThrowsException() {
            assertThatThrownBy(() -> TronAddress.fromBase58("invalid"))
                    .isInstanceOf(AddressException.class);
        }
    }

    @Nested
    @DisplayName("fromHex 方法")
    class FromHexTest {

        @Test
        @DisplayName("解析十六进制地址")
        void parseHexAddress() {
            TronAddress address = TronAddress.fromHex(KNOWN_ADDRESS_HEX);

            assertThat(address).isNotNull();
            assertThat(address.toHex()).isEqualTo(KNOWN_ADDRESS_HEX);
        }

        @Test
        @DisplayName("解析带 0x 前缀的地址")
        void parseHexWithPrefix() {
            TronAddress address = TronAddress.fromHex("0x" + KNOWN_ADDRESS_HEX);

            assertThat(address.toHex()).isEqualTo(KNOWN_ADDRESS_HEX);
        }

        @Test
        @DisplayName("无效十六进制抛出异常")
        void invalidHexThrowsException() {
            assertThatThrownBy(() -> TronAddress.fromHex("invalid"))
                    .isInstanceOf(AddressException.class);
        }
    }

    @Nested
    @DisplayName("fromPublicKey 方法")
    class FromPublicKeyTest {

        // 私钥 1 对应的公钥
        private static final String PUBLIC_KEY_HEX = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

        @Test
        @DisplayName("从 65 字节公钥派生")
        void deriveFrom65BytePublicKey() {
            byte[] publicKey = hexToBytes(PUBLIC_KEY_HEX);
            TronAddress address = TronAddress.fromPublicKey(publicKey);

            assertThat(address).isNotNull();
            assertThat(address.toBase58()).isEqualTo(KNOWN_ADDRESS);
        }

        @Test
        @DisplayName("从 64 字节公钥派生")
        void deriveFrom64BytePublicKey() {
            byte[] publicKey65 = hexToBytes(PUBLIC_KEY_HEX);
            byte[] publicKey64 = new byte[64];
            System.arraycopy(publicKey65, 1, publicKey64, 0, 64);

            TronAddress address = TronAddress.fromPublicKey(publicKey64);
            assertThat(address.toBase58()).isEqualTo(KNOWN_ADDRESS);
        }

        @Test
        @DisplayName("无效公钥长度抛出异常")
        void invalidLengthThrowsException() {
            assertThatThrownBy(() -> TronAddress.fromPublicKey(new byte[32]))
                    .isInstanceOf(AddressException.class);
        }
    }

    @Nested
    @DisplayName("isValid 方法")
    class IsValidTest {

        @Test
        @DisplayName("有效 Base58 地址返回 true")
        void validBase58ReturnsTrue() {
            assertThat(TronAddress.isValid(KNOWN_ADDRESS)).isTrue();
        }

        @Test
        @DisplayName("有效十六进制地址返回 true")
        void validHexReturnsTrue() {
            assertThat(TronAddress.isValid(KNOWN_ADDRESS_HEX)).isTrue();
        }

        @Test
        @DisplayName("带 0x 前缀的十六进制地址返回 true")
        void validHexWithPrefixReturnsTrue() {
            assertThat(TronAddress.isValid("0x" + KNOWN_ADDRESS_HEX)).isTrue();
        }

        @Test
        @DisplayName("空值返回 false")
        void nullReturnsFalse() {
            assertThat(TronAddress.isValid(null)).isFalse();
        }

        @Test
        @DisplayName("空字符串返回 false")
        void emptyReturnsFalse() {
            assertThat(TronAddress.isValid("")).isFalse();
        }

        @Test
        @DisplayName("无效地址返回 false")
        void invalidReturnsFalse() {
            assertThat(TronAddress.isValid("invalid")).isFalse();
        }

        @Test
        @DisplayName("不以 T 开头的 Base58 返回 false")
        void notStartingWithTReturnsFalse() {
            assertThat(TronAddress.isValid("ABC123")).isFalse();
        }
    }

    @Nested
    @DisplayName("格式转换")
    class FormatConversionTest {

        @Test
        @DisplayName("Base58 和 Hex 互转")
        void base58HexRoundTrip() {
            TronAddress fromBase58 = TronAddress.fromBase58(KNOWN_ADDRESS);
            TronAddress fromHex = TronAddress.fromHex(fromBase58.toHex());

            assertThat(fromHex.toBase58()).isEqualTo(KNOWN_ADDRESS);
        }

        @Test
        @DisplayName("toBase58 返回 T 开头地址")
        void toBase58StartsWithT() {
            TronAddress address = TronAddress.fromHex(KNOWN_ADDRESS_HEX);
            assertThat(address.toBase58()).startsWith("T");
        }

        @Test
        @DisplayName("toHex 返回 41 开头地址")
        void toHexStartsWith41() {
            TronAddress address = TronAddress.fromBase58(KNOWN_ADDRESS);
            assertThat(address.toHex()).startsWith("41");
        }
    }

    @Nested
    @DisplayName("equals 和 hashCode")
    class EqualsHashCodeTest {

        @Test
        @DisplayName("相同地址相等")
        void sameAddressEqual() {
            TronAddress a = TronAddress.fromBase58(KNOWN_ADDRESS);
            TronAddress b = TronAddress.fromBase58(KNOWN_ADDRESS);

            assertThat(a).isEqualTo(b);
            assertThat(a.hashCode()).isEqualTo(b.hashCode());
        }

        @Test
        @DisplayName("不同来源相同地址相等")
        void differentSourceSameAddressEqual() {
            TronAddress fromBase58 = TronAddress.fromBase58(KNOWN_ADDRESS);
            TronAddress fromHex = TronAddress.fromHex(KNOWN_ADDRESS_HEX);

            assertThat(fromBase58).isEqualTo(fromHex);
        }
    }

    @Nested
    @DisplayName("toString 方法")
    class ToStringTest {

        @Test
        @DisplayName("toString 返回 Base58 格式")
        void toStringReturnsBase58() {
            TronAddress address = TronAddress.fromHex(KNOWN_ADDRESS_HEX);
            assertThat(address.toString()).isEqualTo(KNOWN_ADDRESS);
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

package io.github.superedison.web3.chain.evm.address;

import io.github.superedison.web3.chain.exception.AddressException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;

/**
 * EvmAddress 单元测试
 * 测试 EVM 地址的创建、解析和验证
 */
@DisplayName("EvmAddress EVM地址测试")
class EvmAddressTest {

    // 测试用已知地址（来自以太坊测试向量）
    private static final String VALID_CHECKSUM_ADDRESS = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    private static final String VALID_LOWERCASE_ADDRESS = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
    private static final byte[] VALID_ADDRESS_BYTES = hexToBytes("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");

    // 测试私钥对应的公钥和地址（私钥=1的标准测试向量）
    private static final String TEST_ADDRESS = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
    private static final byte[] TEST_PUBLIC_KEY = hexToBytes(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
                    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

    @Nested
    @DisplayName("fromBytes 方法测试")
    class FromBytesTest {

        @Test
        @DisplayName("有效的20字节应该成功创建地址")
        void validBytesCreateAddress() {
            EvmAddress address = EvmAddress.fromBytes(VALID_ADDRESS_BYTES);

            assertThat(address).isNotNull();
            assertThat(address.toBytes()).hasSize(20);
        }

        @Test
        @DisplayName("返回的字节应该是副本")
        void toBytesReturnsCopy() {
            EvmAddress address = EvmAddress.fromBytes(VALID_ADDRESS_BYTES);
            byte[] bytes1 = address.toBytes();
            byte[] bytes2 = address.toBytes();

            bytes1[0] = (byte) 0xFF;
            assertThat(bytes2[0]).isNotEqualTo((byte) 0xFF);
        }

        @Test
        @DisplayName("null应该抛出异常")
        void nullThrowsException() {
            assertThatThrownBy(() -> EvmAddress.fromBytes(null))
                    .isInstanceOf(AddressException.class)
                    .hasMessageContaining("20 bytes");
        }

        @Test
        @DisplayName("短字节数组应该抛出异常")
        void shortBytesThrowsException() {
            byte[] shortBytes = new byte[19];
            assertThatThrownBy(() -> EvmAddress.fromBytes(shortBytes))
                    .isInstanceOf(AddressException.class)
                    .hasMessageContaining("20 bytes");
        }

        @Test
        @DisplayName("长字节数组应该抛出异常")
        void longBytesThrowsException() {
            byte[] longBytes = new byte[21];
            assertThatThrownBy(() -> EvmAddress.fromBytes(longBytes))
                    .isInstanceOf(AddressException.class);
        }
    }

    @Nested
    @DisplayName("fromHex 方法测试")
    class FromHexTest {

        @Test
        @DisplayName("带0x前缀的小写地址应该成功解析")
        void parseLowercaseWithPrefix() {
            EvmAddress address = EvmAddress.fromHex(VALID_LOWERCASE_ADDRESS);

            assertThat(address).isNotNull();
            assertThat(address.toHex()).isEqualTo(VALID_LOWERCASE_ADDRESS);
        }

        @Test
        @DisplayName("不带0x前缀的地址应该成功解析")
        void parseWithoutPrefix() {
            EvmAddress address = EvmAddress.fromHex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");

            assertThat(address).isNotNull();
            assertThat(address.toHex()).isEqualTo(VALID_LOWERCASE_ADDRESS);
        }

        @Test
        @DisplayName("大写0X前缀应该成功解析")
        void parseUppercasePrefix() {
            EvmAddress address = EvmAddress.fromHex("0X5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED");

            assertThat(address).isNotNull();
        }

        @Test
        @DisplayName("EIP-55校验和地址应该成功解析")
        void parseChecksumAddress() {
            EvmAddress address = EvmAddress.fromHex(VALID_CHECKSUM_ADDRESS);

            assertThat(address).isNotNull();
            assertThat(address.toChecksumHex()).isEqualTo(VALID_CHECKSUM_ADDRESS);
        }

        @ParameterizedTest
        @DisplayName("无效格式应该抛出异常")
        @ValueSource(strings = {
                "",
                "0x",
                "0x123",
                "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
                "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed00",
                "not_hex",
                "5aaeb6053f3e94c9b9a09f33669435e7ef1beae" // 39 chars
        })
        void invalidFormatThrowsException(String invalidAddress) {
            assertThatThrownBy(() -> EvmAddress.fromHex(invalidAddress))
                    .isInstanceOf(AddressException.class);
        }

        @Test
        @DisplayName("null应该抛出异常")
        void nullThrowsException() {
            assertThatThrownBy(() -> EvmAddress.fromHex(null))
                    .isInstanceOf(AddressException.class);
        }
    }

    @Nested
    @DisplayName("fromPublicKey 方法测试")
    class FromPublicKeyTest {

        @Test
        @DisplayName("65字节公钥（04前缀）应该正确派生地址")
        void deriveFrom65BytePublicKey() {
            EvmAddress address = EvmAddress.fromPublicKey(TEST_PUBLIC_KEY);

            assertThat(address.toChecksumHex()).isEqualToIgnoringCase(TEST_ADDRESS);
        }

        @Test
        @DisplayName("64字节公钥（无前缀）应该正确派生地址")
        void deriveFrom64BytePublicKey() {
            byte[] publicKey64 = Arrays.copyOfRange(TEST_PUBLIC_KEY, 1, 65);
            EvmAddress address = EvmAddress.fromPublicKey(publicKey64);

            assertThat(address.toChecksumHex()).isEqualToIgnoringCase(TEST_ADDRESS);
        }

        @Test
        @DisplayName("无效长度公钥应该抛出异常")
        void invalidLengthThrowsException() {
            byte[] invalidKey = new byte[32];
            assertThatThrownBy(() -> EvmAddress.fromPublicKey(invalidKey))
                    .isInstanceOf(AddressException.class)
                    .hasMessageContaining("public key");
        }

        @Test
        @DisplayName("已知测试向量验证")
        void knownTestVector() {
            // 使用私钥=1的标准测试向量
            byte[] publicKey = hexToBytes(
                    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
                            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

            EvmAddress address = EvmAddress.fromPublicKey(publicKey);

            assertThat(address.toChecksumHex()).isEqualToIgnoringCase(
                    "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
        }
    }

    @Nested
    @DisplayName("isValid 静态方法测试")
    class IsValidStaticTest {

        @ParameterizedTest
        @DisplayName("有效地址应该返回true")
        @ValueSource(strings = {
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0xFb6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb"
        })
        void validAddressReturnsTrue(String address) {
            assertThat(EvmAddress.isValid(address)).isTrue();
        }

        @ParameterizedTest
        @DisplayName("无效地址应该返回false")
        @ValueSource(strings = {
                "",
                "0x",
                "0x123",
                "0xGGGG",
                "not_an_address"
        })
        void invalidAddressReturnsFalse(String address) {
            assertThat(EvmAddress.isValid(address)).isFalse();
        }

        @Test
        @DisplayName("null应该返回false")
        void nullReturnsFalse() {
            assertThat(EvmAddress.isValid(null)).isFalse();
        }
    }

    @Nested
    @DisplayName("toHex 方法测试")
    class ToHexTest {

        @Test
        @DisplayName("应该返回带0x前缀的小写十六进制")
        void returnsLowercaseHex() {
            EvmAddress address = EvmAddress.fromHex(VALID_CHECKSUM_ADDRESS);
            String hex = address.toHex();

            assertThat(hex)
                    .startsWith("0x")
                    .hasSize(42)
                    .isEqualTo(VALID_LOWERCASE_ADDRESS);
        }
    }

    @Nested
    @DisplayName("toChecksumHex 方法测试")
    class ToChecksumHexTest {

        @Test
        @DisplayName("应该返回EIP-55校验和格式")
        void returnsChecksumFormat() {
            EvmAddress address = EvmAddress.fromHex(VALID_LOWERCASE_ADDRESS);
            String checksum = address.toChecksumHex();

            assertThat(checksum).isEqualTo(VALID_CHECKSUM_ADDRESS);
        }

        @Test
        @DisplayName("已知的EIP-55测试向量")
        void eip55TestVectors() {
            // EIP-55 规范中的测试向量
            assertThat(EvmAddress.fromHex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").toChecksumHex())
                    .isEqualTo("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");

            assertThat(EvmAddress.fromHex("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359").toChecksumHex())
                    .isEqualTo("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");

            assertThat(EvmAddress.fromHex("0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb").toChecksumHex())
                    .isEqualTo("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");

            assertThat(EvmAddress.fromHex("0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb").toChecksumHex())
                    .isEqualTo("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
        }
    }

    @Nested
    @DisplayName("equals 和 hashCode 测试")
    class EqualsHashCodeTest {

        @Test
        @DisplayName("相同地址应该相等")
        void sameAddressesAreEqual() {
            EvmAddress address1 = EvmAddress.fromHex(VALID_LOWERCASE_ADDRESS);
            EvmAddress address2 = EvmAddress.fromHex(VALID_CHECKSUM_ADDRESS);

            assertThat(address1).isEqualTo(address2);
            assertThat(address1.hashCode()).isEqualTo(address2.hashCode());
        }

        @Test
        @DisplayName("不同地址应该不相等")
        void differentAddressesAreNotEqual() {
            EvmAddress address1 = EvmAddress.fromHex("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
            EvmAddress address2 = EvmAddress.fromHex("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359");

            assertThat(address1).isNotEqualTo(address2);
        }

        @Test
        @DisplayName("与自身应该相等")
        void equalToSelf() {
            EvmAddress address = EvmAddress.fromHex(VALID_LOWERCASE_ADDRESS);

            assertThat(address).isEqualTo(address);
        }

        @Test
        @DisplayName("与null不相等")
        void notEqualToNull() {
            EvmAddress address = EvmAddress.fromHex(VALID_LOWERCASE_ADDRESS);

            assertThat(address).isNotEqualTo(null);
        }
    }

    @Nested
    @DisplayName("toString 方法测试")
    class ToStringTest {

        @Test
        @DisplayName("toString应该返回校验和格式")
        void toStringReturnsChecksum() {
            EvmAddress address = EvmAddress.fromHex(VALID_LOWERCASE_ADDRESS);

            assertThat(address.toString()).isEqualTo(VALID_CHECKSUM_ADDRESS);
        }
    }

    @Nested
    @DisplayName("toBase58 方法测试（接口兼容）")
    class ToBase58Test {

        @Test
        @DisplayName("toBase58应该返回校验和地址（EVM无Base58）")
        void toBase58ReturnsChecksumHex() {
            EvmAddress address = EvmAddress.fromHex(VALID_LOWERCASE_ADDRESS);

            assertThat(address.toBase58()).isEqualTo(VALID_CHECKSUM_ADDRESS);
        }
    }

    @Nested
    @DisplayName("isValid 实例方法测试")
    class IsValidInstanceTest {

        @Test
        @DisplayName("有效创建的地址应该返回true")
        void validAddressReturnsTrue() {
            EvmAddress address = EvmAddress.fromHex(VALID_CHECKSUM_ADDRESS);

            assertThat(address.isValid()).isTrue();
        }
    }

    // 辅助方法
    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
package io.github.superedison.web3.crypto.eip712;

import io.github.superedison.web3.crypto.hash.Keccak256;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EIP-712 编码器（链无关核心）")
class Eip712EncoderTest {

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder("0x");
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** 规范经典 Mail 示例（Ether Mail 域，0x-hex 地址）——同时用作核心编码向量 Vector A。 */
    private static Eip712TypedData mail(String contents) {
        return Eip712TypedData.builder()
                .domain(Eip712Domain.builder()
                        .name("Ether Mail")
                        .version("1")
                        .chainId(1)
                        .verifyingContract("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
                        .build())
                .addType("Person",
                        new Eip712TypedData.Field("name", "string"),
                        new Eip712TypedData.Field("wallet", "address"))
                .addType("Mail",
                        new Eip712TypedData.Field("from", "Person"),
                        new Eip712TypedData.Field("to", "Person"),
                        new Eip712TypedData.Field("contents", "string"))
                .primaryType("Mail")
                .message(Map.of(
                        "from", Map.of("name", "Cow", "wallet", "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"),
                        "to", Map.of("name", "Bob", "wallet", "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                        "contents", contents))
                .build();
    }

    private static Eip712TypedData mail() {
        return mail("Hello, Bob!");
    }

    @Nested
    @DisplayName("encodeType / typeHash")
    class EncodeType {

        @Test
        @DisplayName("AssetTransfer 逐字节匹配 TIP-712 规范给出的类型串（含 trcToken）")
        void assetTransferMatchesSpec() {
            Eip712TypedData data = Eip712TypedData.builder()
                    .domain(Eip712Domain.builder().name("x").build())
                    .addType("AssetTransfer",
                            new Eip712TypedData.Field("from", "address"),
                            new Eip712TypedData.Field("to", "address"),
                            new Eip712TypedData.Field("id", "trcToken"),
                            new Eip712TypedData.Field("amount", "uint256"),
                            new Eip712TypedData.Field("v", "uint8"),
                            new Eip712TypedData.Field("r", "bytes32"),
                            new Eip712TypedData.Field("s", "bytes32"))
                    .primaryType("AssetTransfer")
                    .message(Map.of("from", "0x", "to", "0x", "id", 1, "amount", 1, "v", 1, "r", "0x", "s", "0x"))
                    .build();
            assertThat(new Eip712Encoder(data).encodeType("AssetTransfer")).isEqualTo(
                    "AssetTransfer(address from,address to,trcToken id,uint256 amount,uint8 v,bytes32 r,bytes32 s)");
        }

        @Test
        @DisplayName("被引用的 struct 依赖按字母序排在主类型之后")
        void sortsDependenciesAlphabetically() {
            assertThat(new Eip712Encoder(mail()).encodeType("Mail")).isEqualTo(
                    "Mail(Person from,Person to,string contents)Person(string name,address wallet)");
        }

        @Test
        @DisplayName("typeHash = keccak256(encodeType)")
        void typeHashIsKeccakOfEncodeType() {
            byte[] expected = Keccak256.hash(
                    "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
                            .getBytes(StandardCharsets.UTF_8));
            assertThat(new Eip712Encoder(mail()).typeHash("Mail")).isEqualTo(expected);
        }
    }

    @Nested
    @DisplayName("默认地址编解码 / 原子类型")
    class Encoding {

        private final Eip712Encoder enc = new Eip712Encoder(mail());

        @Test
        @DisplayName("DEFAULT codec：21 字节 0x41 前缀被剥离；0x-hex 与 20 字节主体一致，左填充")
        void defaultAddressCodec() {
            byte[] body = new byte[20];
            for (int i = 0; i < 20; i++) body[i] = (byte) (i + 1);
            byte[] full41 = new byte[21];
            full41[0] = 0x41;
            System.arraycopy(body, 0, full41, 1, 20);

            byte[] expected = new byte[32];
            System.arraycopy(body, 0, expected, 12, 20);

            assertThat(enc.encodeValue("address", full41)).isEqualTo(expected);
            assertThat(enc.encodeValue("address", body)).isEqualTo(expected);
            assertThat(enc.encodeValue("address", "0x" + hex(body).substring(2))).isEqualTo(expected);
        }

        @Test
        @DisplayName("trcToken 按 uint256 编码")
        void trcTokenAsUint256() {
            assertThat(enc.encodeValue("trcToken", 1_000_000L))
                    .isEqualTo(Eip712Encoder.toBytes32(BigInteger.valueOf(1_000_000L)));
        }

        @Test
        @DisplayName("uint256 / bool / string / bytes / bytes32")
        void atomics() {
            byte[] one = new byte[32];
            one[31] = 1;
            assertThat(enc.encodeValue("uint256", BigInteger.ONE)).isEqualTo(one);
            assertThat(enc.encodeValue("bool", true)[31]).isEqualTo((byte) 1);
            assertThat(enc.encodeValue("bool", false)[31]).isEqualTo((byte) 0);
            assertThat(enc.encodeValue("string", "Hello, Bob!"))
                    .isEqualTo(Keccak256.hash("Hello, Bob!".getBytes(StandardCharsets.UTF_8)));
            byte[] raw = {1, 2, 3, 4};
            assertThat(enc.encodeValue("bytes", raw)).isEqualTo(Keccak256.hash(raw));
            byte[] v32 = new byte[32];
            v32[0] = (byte) 0xaa;
            assertThat(enc.encodeValue("bytes32", v32)).isEqualTo(v32);
        }
    }

    @Nested
    @DisplayName("输入校验（不静默错编码）")
    class Hardening {

        private final Eip712Encoder enc = new Eip712Encoder(mail());

        @Test
        @DisplayName("bool 接受 true/1/\"1\"，绝不把真值意图静默编成 false")
        void boolTruthyExplicit() {
            assertThat(enc.encodeValue("bool", true)[31]).isEqualTo((byte) 1);
            assertThat(enc.encodeValue("bool", 1)[31]).isEqualTo((byte) 1);
            assertThat(enc.encodeValue("bool", "1")[31]).isEqualTo((byte) 1);
            assertThat(enc.encodeValue("bool", 0)[31]).isEqualTo((byte) 0);
        }

        @Test
        @DisplayName("bool 遇歧义值抛异常；uint/int 越界抛异常；裸 uint/int 被拒")
        void rejectsBadInput() {
            assertThatThrownBy(() -> enc.encodeValue("bool", 5)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("bool", "yes")).isInstanceOf(IllegalArgumentException.class);
            assertThat(enc.encodeValue("uint8", 255)[31]).isEqualTo((byte) 0xff);
            assertThatThrownBy(() -> enc.encodeValue("uint8", 256)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("uint256", BigInteger.valueOf(-1))).isInstanceOf(IllegalArgumentException.class);
            assertThat(enc.encodeValue("int8", -128)).hasSize(32);
            assertThatThrownBy(() -> enc.encodeValue("int8", 128)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("uint", 1)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("int", 1)).isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("numeric bool 必须精确为 0/1，不允许 longValue 缩窄或小数截断")
        void numericBoolMustBeExact() {
            BigInteger twoTo64 = BigInteger.ONE.shiftLeft(64);
            assertThatThrownBy(() -> enc.encodeValue("bool", twoTo64)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("bool", twoTo64.add(BigInteger.ONE)))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("bool", new BigDecimal("0.9")))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("bool", 1.9d)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("bool", Double.NaN)).isInstanceOf(IllegalArgumentException.class);
            assertThat(enc.encodeValue("bool", BigDecimal.ONE)[31]).isEqualTo((byte) 1);
        }

        @Test
        @DisplayName("hexToBytes 拒绝 +/- 等非法字符（bytesN / address）")
        void rejectsMalformedHex() {
            assertThatThrownBy(() -> enc.encodeValue("bytes4", "0x-1000000")).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("bytes", "0x-1")).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("address", "0x" + "-0".repeat(20))).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("int256", "0x-1")).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("int256", "0x+1")).isInstanceOf(IllegalArgumentException.class);
            assertThat(enc.encodeValue("int256", "0x01")).isEqualTo(Eip712Encoder.toBytes32(BigInteger.ONE));
        }

        @Test
        @DisplayName("十进制整数仅接受 ASCII 数字，拒绝 Unicode 数字混淆")
        void rejectsUnicodeDecimalDigits() {
            assertThatThrownBy(() -> enc.encodeValue("uint256", "\u0661"))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("int256", "1\uFF10"))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThat(enc.encodeValue("int256", "+1"))
                    .isEqualTo(Eip712Encoder.toBytes32(BigInteger.ONE));
            assertThat(enc.encodeValue("int256", "-1"))
                    .isEqualTo(Eip712Encoder.toBytes32(BigInteger.ONE.negate()));
        }

        @Test
        @DisplayName("trcToken >= 2^256 抛异常，边界内仍可编码")
        void trcTokenWidthEnforced() {
            BigInteger twoTo256 = BigInteger.ONE.shiftLeft(256);
            assertThatThrownBy(() -> enc.encodeValue("trcToken", twoTo256))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("uint256", twoTo256))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> Eip712Encoder.toBytes32(twoTo256))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> Eip712Encoder.toBytes32(BigInteger.ONE.shiftLeft(255).negate().subtract(BigInteger.ONE)))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThat(enc.encodeValue("trcToken", twoTo256.subtract(BigInteger.ONE))).hasSize(32);
        }

        @Test
        @DisplayName("string 拒绝未配对 surrogate，合法代理对仍按 UTF-8 编码")
        void rejectsMalformedUtf16() {
            String loneHigh = String.valueOf((char) 0xD800);
            String loneLow = String.valueOf((char) 0xDC00);
            assertThatThrownBy(() -> enc.encodeValue("string", loneHigh)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> enc.encodeValue("string", loneLow)).isInstanceOf(IllegalArgumentException.class);

            String validPair = new String(Character.toChars(0x1F600));
            assertThat(enc.encodeValue("string", validPair))
                    .isEqualTo(Keccak256.hash(validPair.getBytes(StandardCharsets.UTF_8)));
        }

        @Test
        @DisplayName("schema 名称拒绝未配对 surrogate，避免不同类型定义哈希碰撞")
        void rejectsMalformedUtf16InSchema() {
            String loneHigh = String.valueOf((char) 0xD800);
            String loneLow = String.valueOf((char) 0xDC00);

            assertThatThrownBy(() -> encoderWithFieldName(loneHigh).digest())
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> encoderWithFieldName(loneLow).digest())
                    .isInstanceOf(IllegalArgumentException.class);
        }

        private Eip712Encoder encoderWithFieldName(String fieldName) {
            Eip712TypedData data = Eip712TypedData.builder()
                    .domain(Eip712Domain.builder().name("schema-test").build())
                    .addType("Payload", new Eip712TypedData.Field(fieldName, "uint256"))
                    .primaryType("Payload")
                    .message(Map.of(fieldName, 1))
                    .build();
            return new Eip712Encoder(data);
        }
    }

    @Nested
    @DisplayName("Vector A — EIP-712 经典 Mail（四来源确认的核心编码）")
    class VectorA {

        @Test
        @DisplayName("typeHash / domainSeparator / hashStruct / digest 全部匹配")
        void allHashesMatch() {
            Eip712Encoder enc = new Eip712Encoder(mail());
            assertThat(hex(enc.typeHash("EIP712Domain")))
                    .isEqualTo("0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");
            assertThat(hex(enc.typeHash("Person")))
                    .isEqualTo("0xb9d8c78acf9b987311de6c7b45bb6a9c8e1bf361fa7fd3467a2163f994c79500");
            assertThat(hex(enc.typeHash("Mail")))
                    .isEqualTo("0xa0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2");
            assertThat(hex(enc.domainSeparator()))
                    .isEqualTo("0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");
            assertThat(hex(enc.hashStruct("Mail", mail().message())))
                    .isEqualTo("0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e");
            assertThat(hex(enc.digest()))
                    .isEqualTo("0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
        }
    }

    @Nested
    @DisplayName("部分域 / 稳定性")
    class Misc {

        @Test
        @DisplayName("缺省 name/salt 时 EIP712Domain 类型串只含存在字段")
        void partialDomain() {
            Eip712TypedData data = Eip712TypedData.builder()
                    .domain(Eip712Domain.builder()
                            .version("34.14.0").chainId(364)
                            .verifyingContract("0xd8746C2F080aeB0e62098d236E238B03E0F70215").build())
                    .addType("S", new Eip712TypedData.Field("p3", "address"))
                    .primaryType("S")
                    .message(Map.of("p3", "0x576CAA13F2d1F09973d8373d31fD4c4f12DBdf61"))
                    .build();
            assertThat(new Eip712Encoder(data).encodeType("EIP712Domain"))
                    .isEqualTo("EIP712Domain(string version,uint256 chainId,address verifyingContract)");
        }

        @Test
        @DisplayName("相同输入产生相同摘要；改动消息则摘要改变")
        void digestStability() {
            byte[] d1 = new Eip712Encoder(mail("Hello, Bob!")).digest();
            byte[] d2 = new Eip712Encoder(mail("Hello, Bob!")).digest();
            byte[] d3 = new Eip712Encoder(mail("Hello, Alice!")).digest();
            assertThat(d1).hasSize(32).isEqualTo(d2);
            assertThat(d3).isNotEqualTo(d1);
        }
    }
}

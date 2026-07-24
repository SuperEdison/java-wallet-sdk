package io.github.superedison.web3.crypto.eip712;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EIP-712 schema 规范校验")
class Eip712TypedDataSchemaValidationTest {

    @Test
    @DisplayName("struct 与字段名仅接受 Solidity 标识符，拒绝 encodeType 分隔符注入")
    void rejectsIdentifierInjection() {
        assertThatThrownBy(() -> dataWithSchema(
                "Payload(uint256 injected)",
                new Eip712TypedData.Field("value", "uint256")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("identifier");

        assertThatThrownBy(() -> dataWithSchema(
                "Payload",
                new Eip712TypedData.Field("value,bytes32 injected", "uint256")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("identifier");

        assertThatThrownBy(() -> dataWithSchema(
                "Payload",
                new Eip712TypedData.Field("value", "uint256)Injected(bytes32")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("identifier");
    }

    @Test
    @DisplayName("struct 名不能遮蔽原子类型")
    void rejectsAtomicTypeShadowing() {
        for (String name : List.of(
                "address", "bool", "string", "bytes", "bytes32",
                "uint", "uint256", "int8", "trcToken")) {
            assertThatThrownBy(() -> dataWithSchema(
                    name, new Eip712TypedData.Field("value", "uint256")))
                    .as(name)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("conflicts with an atomic type");
        }
    }

    @Test
    @DisplayName("拒绝重复字段、未知类型、非规范位宽和畸形固定数组")
    void rejectsMalformedFieldDeclarations() {
        assertThatThrownBy(() -> dataWithSchema(
                "Payload",
                new Eip712TypedData.Field("value", "uint256"),
                new Eip712TypedData.Field("value", "bytes32")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Duplicate field");

        for (String type : List.of(
                "Unknown", "uint", "int", "uint7", "uint08", "bytes0", "bytes33",
                "uint256[0]", "uint256[01]", "uint256[-1]", "uint256[999999999999999999999]",
                "uint256[2", "uint256]", "uint256[2]garbage")) {
            assertThatThrownBy(() -> dataWithSchema(
                    "Payload", new Eip712TypedData.Field("value", type)))
                    .as(type)
                    .isInstanceOf(IllegalArgumentException.class);
        }

        String excessiveDimensions = "uint256" + "[]".repeat(128);
        assertThatThrownBy(() -> dataWithSchema(
                "Payload", new Eip712TypedData.Field("value", excessiveDimensions)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("array nesting exceeds");
    }

    @Test
    @DisplayName("允许前向/自递归引用、多维数组及 _/$ 标识符")
    void acceptsValidRecursiveAndForwardReferences() {
        Eip712TypedData forward = Eip712TypedData.builder()
                .domain(Eip712Domain.builder().name("schema").build())
                .addType("$Root_", new Eip712TypedData.Field("_children$", "Child[][2]"))
                .addType("Child", new Eip712TypedData.Field("value", "uint256"))
                .primaryType("$Root_")
                .message(Map.of("_children$", List.of(List.of(), List.of())))
                .build();
        assertThat(new Eip712Encoder(forward).digest()).hasSize(32);

        Eip712TypedData recursive = Eip712TypedData.builder()
                .domain(Eip712Domain.builder().name("schema").build())
                .addType("Node", new Eip712TypedData.Field("children", "Node[]"))
                .primaryType("Node")
                .message(Map.of("children", List.of()))
                .build();
        assertThat(new Eip712Encoder(recursive).digest()).hasSize(32);
    }

    private static Eip712TypedData dataWithSchema(
            String typeName, Eip712TypedData.Field... fields) {
        return Eip712TypedData.builder()
                .domain(Eip712Domain.builder().name("schema").build())
                .addType(typeName, fields)
                .primaryType(typeName)
                .message(Map.of("value", 1))
                .build();
    }
}

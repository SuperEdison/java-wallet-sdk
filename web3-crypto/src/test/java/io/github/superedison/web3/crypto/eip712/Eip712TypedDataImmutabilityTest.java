package io.github.superedison.web3.crypto.eip712;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EIP-712 DTO 不可变性")
class Eip712TypedDataImmutabilityTest {

    @Test
    @DisplayName("复用 builder 不会改变已构建对象的类型或摘要")
    void builderReuseDoesNotChangeBuiltTypedData() {
        byte[] payload = {1, 2, 3, 4};
        Eip712TypedData.Builder builder = Eip712TypedData.builder()
                .domain(Eip712Domain.builder().name("immutable").build())
                .addType("Payload", new Eip712TypedData.Field("value", "bytes"))
                .primaryType("Payload")
                .message(Map.of("value", payload));

        Eip712TypedData first = builder.build();
        byte[] firstDigest = new Eip712Encoder(first).digest();

        Eip712TypedData second = builder
                .addType("Payload", new Eip712TypedData.Field("value", "bytes4"))
                .message(Map.of("value", new byte[] {9, 8, 7, 6}))
                .build();

        assertThat(first.types().get("Payload").get(0).type()).isEqualTo("bytes");
        assertThat(new Eip712Encoder(first).digest()).isEqualTo(firstDigest);
        assertThat(new Eip712Encoder(second).digest()).isNotEqualTo(firstDigest);
    }

    @Test
    @DisplayName("构建后修改顶层、嵌套 Map/List/Object[]/byte[] 原引用不改变摘要")
    void sourceMutationDoesNotChangeDigest() {
        byte[] raw = {1, 2, 3};
        byte[] childRaw = {4, 5, 6};
        byte[] arrayRaw = {7, 8};
        Map<String, Object> child = new LinkedHashMap<>();
        child.put("label", "before");
        child.put("raw", childRaw);
        List<Object> amounts = new ArrayList<>(List.of(BigInteger.ONE, BigInteger.TWO));
        Object[] chunks = {arrayRaw, new byte[] {9, 10}};
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("raw", raw);
        message.put("child", child);
        message.put("amounts", amounts);
        message.put("chunks", chunks);

        Eip712TypedData data = complexData(message);
        byte[] digest = new Eip712Encoder(data).digest();

        raw[0] = 99;
        childRaw[0] = 99;
        arrayRaw[0] = 99;
        child.put("label", "after");
        amounts.set(0, BigInteger.TEN);
        chunks[0] = new byte[] {99, 99};
        message.clear();

        assertThat(new Eip712Encoder(data).digest()).isEqualTo(digest);
    }

    @Test
    @DisplayName("types/message getter 的容器不可修改，取得的 byte[] 也不暴露内部状态")
    @SuppressWarnings("unchecked")
    void gettersCannotMutateTypedData() {
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("raw", new byte[] {1, 2, 3});
        message.put("child", new LinkedHashMap<>(Map.of(
                "label", "nested",
                "raw", new byte[] {4, 5, 6})));
        message.put("amounts", new ArrayList<>(List.of(BigInteger.ONE, BigInteger.TWO)));
        message.put("chunks", new Object[] {new byte[] {7, 8}, new byte[] {9, 10}});

        Eip712TypedData data = complexData(message);
        byte[] digest = new Eip712Encoder(data).digest();
        Map<String, Object> exposed = data.message();
        Map<String, Object> exposedChild = (Map<String, Object>) exposed.get("child");
        List<Object> exposedAmounts = (List<Object>) exposed.get("amounts");
        List<Object> exposedChunks = (List<Object>) exposed.get("chunks");

        assertThatThrownBy(() -> data.types().put("Other", List.of()))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> data.types().get("Payload").add(
                new Eip712TypedData.Field("other", "string")))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> exposed.put("other", "value"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> exposedChild.put("label", "changed"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> exposedAmounts.add(BigInteger.TEN))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> exposedChunks.set(0, new byte[] {0, 0}))
                .isInstanceOf(UnsupportedOperationException.class);

        Arrays.fill((byte[]) exposed.get("raw"), (byte) 99);
        Arrays.fill((byte[]) exposedChild.get("raw"), (byte) 99);
        Arrays.fill((byte[]) exposedChunks.get(0), (byte) 99);

        assertThat(new Eip712Encoder(data).digest()).isEqualTo(digest);
    }

    @Test
    @DisplayName("Domain 对 verifyingContract byte[] 与 salt 在构建和读取边界均做快照")
    void domainByteArraysAreDefensivelyCopied() {
        byte[] contract = new byte[20];
        byte[] salt = new byte[32];
        contract[19] = 1;
        salt[31] = 2;
        Eip712Domain domain = Eip712Domain.builder()
                .name("immutable-domain")
                .verifyingContract(contract)
                .salt(salt)
                .build();
        Eip712TypedData data = Eip712TypedData.builder()
                .domain(domain)
                .addType("Payload", new Eip712TypedData.Field("value", "uint256"))
                .primaryType("Payload")
                .message(Map.of("value", 1))
                .build();
        byte[] digest = new Eip712Encoder(data).digest();

        Arrays.fill(contract, (byte) 99);
        Arrays.fill(salt, (byte) 99);
        Map<String, Object> exposed = domain.valueMap();
        Arrays.fill((byte[]) exposed.get("verifyingContract"), (byte) 88);
        Arrays.fill((byte[]) exposed.get("salt"), (byte) 88);

        assertThat(new Eip712Encoder(data).digest()).isEqualTo(digest);
        assertThatThrownBy(() -> exposed.put("name", "changed"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("拒绝 Map 自引用以及 List/Object[] 互相引用")
    void cyclicContainersAreRejected() {
        Map<String, Object> self = new LinkedHashMap<>();
        self.put("self", self);
        assertThatThrownBy(() -> singleValueData(self))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Cyclic");

        List<Object> list = new ArrayList<>();
        Object[] array = {list};
        list.add(array);
        assertThatThrownBy(() -> singleValueData(list))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Cyclic");
    }

    @Test
    @DisplayName("共享 DAG 的快照和编码均按唯一节点线性处理")
    void sharedDagIsProcessedOncePerNode() {
        int depth = 20;
        AtomicInteger snapshotVisits = new AtomicInteger();
        Object addressMarker = new Object();
        Map<String, Object> node = new CountingMap(snapshotVisits, Map.of(
                "children", List.of(), "marker", addressMarker));
        for (int i = 0; i < depth; i++) {
            node = new CountingMap(snapshotVisits, Map.of(
                    "children", List.of(node, node), "marker", addressMarker));
        }

        Eip712TypedData data = Eip712TypedData.builder()
                .domain(Eip712Domain.builder().name("dag").build())
                .addType("Node",
                        new Eip712TypedData.Field("children", "Node[]"),
                        new Eip712TypedData.Field("marker", "address"))
                .addType("Root", new Eip712TypedData.Field("node", "Node"))
                .primaryType("Root")
                .message(Map.of("node", node))
                .build();

        AtomicInteger encodedAddresses = new AtomicInteger();
        AddressCodec countingCodec = ignored -> {
            if (encodedAddresses.incrementAndGet() > depth + 1) {
                throw new AssertionError("shared node encoded more than once");
            }
            return new byte[20];
        };

        assertThat(snapshotVisits).hasValue(depth + 1);
        assertThat(new Eip712Encoder(data, countingCodec).digest()).hasSize(32);
        assertThat(encodedAddresses).hasValue(depth + 1);
    }

    @Test
    @DisplayName("过深但无环的消息在栈溢出前被拒绝")
    void excessiveNestingIsRejected() {
        Object nested = "leaf";
        for (int i = 0; i < 140; i++) {
            nested = List.of(nested);
        }
        Object value = nested;

        assertThatThrownBy(() -> singleValueData(value))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("nesting exceeds");
    }

    private static Eip712TypedData complexData(Map<String, Object> message) {
        return Eip712TypedData.builder()
                .domain(Eip712Domain.builder().name("immutable").build())
                .addType("Child",
                        new Eip712TypedData.Field("label", "string"),
                        new Eip712TypedData.Field("raw", "bytes"))
                .addType("Payload",
                        new Eip712TypedData.Field("raw", "bytes"),
                        new Eip712TypedData.Field("child", "Child"),
                        new Eip712TypedData.Field("amounts", "uint256[]"),
                        new Eip712TypedData.Field("chunks", "bytes[]"))
                .primaryType("Payload")
                .message(message)
                .build();
    }

    private static Eip712TypedData singleValueData(Object value) {
        return Eip712TypedData.builder()
                .domain(Eip712Domain.builder().name("cycle-test").build())
                .addType("Payload", new Eip712TypedData.Field("value", "bytes"))
                .primaryType("Payload")
                .message(Map.of("value", value))
                .build();
    }

    private static final class CountingMap extends AbstractMap<String, Object> {
        private final AtomicInteger visits;
        private final Map<String, Object> delegate;

        private CountingMap(AtomicInteger visits, Map<String, Object> delegate) {
            this.visits = visits;
            this.delegate = delegate;
        }

        @Override
        public Set<Entry<String, Object>> entrySet() {
            if (visits.incrementAndGet() > 100) {
                throw new AssertionError("shared DAG was traversed exponentially");
            }
            return delegate.entrySet();
        }
    }
}

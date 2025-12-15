package io.github.superedison.web3.chain.evm.wallet;

import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.HDWallet;
import io.github.superedison.web3.crypto.kdf.Bip32;
import io.github.superedison.web3.crypto.mnemonic.Bip39;
import io.github.superedison.web3.crypto.util.SecureBytes;

import java.util.ArrayList;
import java.util.List;

/**
 * EVM HD 钱包实现，支持 BIP-32/39/44 派生。
 */
public final class EvmHDWallet extends EvmWallet implements HDWallet {

    private final List<String> mnemonic;
    private final String derivationPath;
    private final String passphrase;
    private final Bip32.ExtendedKey extendedKey;

    public EvmHDWallet(List<String> mnemonic, String passphrase, String derivationPath,
                       Bip32.ExtendedKey extendedKey, boolean exportable) {
        super(derivationPath, extendedKey.privateKey(), exportable);
        this.mnemonic = List.copyOf(mnemonic);
        this.derivationPath = derivationPath;
        this.passphrase = passphrase != null ? passphrase : "";
        this.extendedKey = extendedKey;
    }

    @Override
    public List<String> getMnemonic() {
        return List.copyOf(mnemonic);
    }

    @Override
    public String getDerivationPath() {
        return derivationPath;
    }

    @Override
    public HDWallet deriveChild(int index) {
        checkNotDestroyed();
        Bip32.ExtendedKey childKey = Bip32.deriveChild(extendedKey, index);
        String childPath = Bip32.indicesToPath(childKey.path());
        return new EvmHDWallet(mnemonic, passphrase, childPath, childKey, getKeyHolder().canExportPrivateKey());
    }

    @Override
    public HDWallet derivePath(String path) {
        checkNotDestroyed();
        byte[] seed = Bip39.mnemonicToSeed(mnemonic, passphrase);
        try (Bip32.ExtendedKey masterKey = Bip32.masterKeyFromSeed(seed)) {
            Bip32.ExtendedKey target = Bip32.derivePath(masterKey, path);
            return new EvmHDWallet(mnemonic, passphrase, path, target, getKeyHolder().canExportPrivateKey());
        } finally {
            SecureBytes.secureWipe(seed);
        }
    }

    @Override
    public List<Address> deriveAddresses(int startIndex, int count) {
        checkNotDestroyed();
        if (startIndex < 0 || count < 0) {
            throw new IllegalArgumentException("startIndex and count must be non-negative");
        }
        List<Address> addresses = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int index = startIndex + i;
            Bip32.ExtendedKey childKey = Bip32.deriveChild(extendedKey, index);
            try {
                byte[] publicKey = childKey.getUncompressedPublicKey();
                addresses.add(EvmAddress.fromPublicKey(publicKey));
            } finally {
                childKey.destroy();
            }
        }
        return addresses;
    }

    @Override
    public void destroy() {
        super.destroy();
        extendedKey.destroy();
    }

    @Override
    public boolean isDestroyed() {
        return super.isDestroyed() || extendedKey.isDestroyed();
    }

    @Override
    public String toString() {
        return "EvmHDWallet{***REDACTED***}";
    }

    private void checkNotDestroyed() {
        if (isDestroyed()) {
            throw new IllegalStateException("Wallet has been destroyed");
        }
    }
}

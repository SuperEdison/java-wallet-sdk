package io.github.superedison.web3.chain.evm;

import io.github.superedison.web3.chain.ChainAdapter;
import io.github.superedison.web3.chain.ChainType;
import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.chain.evm.internal.EvmSignature;
import io.github.superedison.web3.chain.evm.message.Eip191Prefix;
import io.github.superedison.web3.chain.evm.tx.EvmRawTransaction;
import io.github.superedison.web3.chain.evm.tx.EvmSignedTransaction;
import io.github.superedison.web3.chain.evm.wallet.EvmHDWallet;
import io.github.superedison.web3.chain.evm.wallet.EvmWallet;
import io.github.superedison.web3.chain.exception.AddressException;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.transaction.RawTransaction;
import io.github.superedison.web3.core.transaction.SignedTransaction;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.HDWallet;
import io.github.superedison.web3.core.wallet.Wallet;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.kdf.Bip32;
import io.github.superedison.web3.crypto.mnemonic.Bip39;
import io.github.superedison.web3.crypto.util.SecureBytes;

import java.util.List;

/**
 * EVM 链适配器
 */
public final class EvmChainAdapter implements ChainAdapter {

    @Override
    public ChainType getChainType() {
        return ChainType.EVM;
    }

    // ========== 地址 ==========

    @Override
    public boolean isValidAddress(String address) {
        return EvmAddress.isValid(address);
    }

    @Override
    public Address parseAddress(String address) {
        return EvmAddress.fromHex(address);
    }

    @Override
    public Address deriveAddress(byte[] publicKey) {
        return EvmAddress.fromPublicKey(publicKey);
    }

    // ========== 钱包 ==========

    @Override
    public HDWallet createHDWallet(int wordCount) {
        List<String> mnemonic = Bip39.generateMnemonic(wordCount);
        String path = ChainType.EVM.getDefaultPath();
        return fromMnemonic(mnemonic, "", path);
    }

    @Override
    public HDWallet fromMnemonic(List<String> mnemonic, String passphrase, String path) {
        String finalPath = (path == null || path.isEmpty()) ? ChainType.EVM.getDefaultPath() : path;
        byte[] seed = Bip39.mnemonicToSeed(mnemonic, passphrase != null ? passphrase : "");
        try (Bip32.ExtendedKey masterKey = Bip32.masterKeyFromSeed(seed)) {
            Bip32.ExtendedKey derivedKey = Bip32.derivePath(masterKey, finalPath);
            return new EvmHDWallet(mnemonic, passphrase, finalPath, derivedKey, true);
        } finally {
            SecureBytes.secureWipe(seed);
        }
    }

    @Override
    public Wallet fromPrivateKey(byte[] privateKey) {
        return new EvmWallet(null, privateKey, true);
    }

    // ========== 交易 ==========

    @Override
    public byte[] encodeTransaction(RawTransaction transaction) {
        if (!(transaction instanceof EvmRawTransaction evmTx)) {
            throw new IllegalArgumentException("Expected EvmRawTransaction");
        }
        return evmTx.encode();
    }

    @Override
    public byte[] hashTransaction(RawTransaction transaction) {
        if (!(transaction instanceof EvmRawTransaction evmTx)) {
            throw new IllegalArgumentException("Expected EvmRawTransaction");
        }
        return evmTx.hash();
    }

    @Override
    public byte[] encodeSignedTransaction(SignedTransaction transaction) {
        if (!(transaction instanceof EvmSignedTransaction evmTx)) {
            throw new IllegalArgumentException("Expected EvmSignedTransaction");
        }
        return evmTx.encode();
    }

    // ========== 签名 ==========

    @Override
    public byte[] hashMessage(byte[] message) {
        return Eip191Prefix.hash(message);
    }

    @Override
    public Address recoverSigner(byte[] hash, Signature signature) {
        if (hash == null || hash.length != 32) {
            throw new IllegalArgumentException("Hash must be 32 bytes");
        }

        byte[] sigBytes = signature.bytes();
        if (sigBytes.length != 65) {
            throw new IllegalArgumentException("Signature must be 65 bytes");
        }

        EvmSignature evmSig = EvmSignature.fromCompact(sigBytes);
        int recoveryId = evmSig.getRecoveryId();

        byte[] publicKey = Secp256k1Signer.recoverPublicKey(
                hash,
                evmSig.getR(),
                evmSig.getS(),
                recoveryId
        );

        if (publicKey == null) {
            throw new AddressException("Failed to recover public key from signature");
        }

        return EvmAddress.fromPublicKey(publicKey);
    }
}

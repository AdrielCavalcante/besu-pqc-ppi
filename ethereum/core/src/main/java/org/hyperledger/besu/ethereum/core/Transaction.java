/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.core;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import static org.hyperledger.besu.crypto.Hash.keccak256;
import static org.hyperledger.besu.datatypes.VersionedHash.SHA256_VERSION_ID;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;
import org.apache.tuweni.units.bigints.UInt256s;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.AccessListEntry;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.BlobType;
import org.hyperledger.besu.datatypes.BytesHolder;
import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Sha256Hash;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.VersionedHash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.encoding.AccessListTransactionEncoder;
import org.hyperledger.besu.ethereum.core.encoding.BlobTransactionEncoder;
import org.hyperledger.besu.ethereum.core.encoding.CodeDelegationEncoder;
import org.hyperledger.besu.ethereum.core.encoding.EncodingContext;
import org.hyperledger.besu.ethereum.core.encoding.FlexibleAccessListTransactionEncoder;
import org.hyperledger.besu.ethereum.core.encoding.TransactionDecoder;
import org.hyperledger.besu.ethereum.core.encoding.TransactionEncoder;
import org.hyperledger.besu.ethereum.core.kzg.Blob;
import org.hyperledger.besu.ethereum.core.kzg.BlobsWithCommitments;
import org.hyperledger.besu.ethereum.core.kzg.KZGCommitment;
import org.hyperledger.besu.ethereum.core.kzg.KZGProof;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.primitives.Longs;

/** An operation submitted by an external actor to be applied to the system. */
public class Transaction
    implements org.hyperledger.besu.datatypes.Transaction,
        org.hyperledger.besu.plugin.data.UnsignedPrivateMarkerTransaction {

  // Used for transactions that are not tied to a specific chain
  // (e.g. does not have a chain id associated with it).
  public static final BigInteger REPLAY_UNPROTECTED_V_BASE = BigInteger.valueOf(27);
  public static final BigInteger REPLAY_UNPROTECTED_V_BASE_PLUS_1 = BigInteger.valueOf(28);

  public static final BigInteger REPLAY_PROTECTED_V_BASE = BigInteger.valueOf(35);

  // The v signature parameter starts at 36 because 1 is the first valid chainId so:
  // chainId > 1 implies that 2 * chainId + V_BASE > 36.
  public static final BigInteger REPLAY_PROTECTED_V_MIN = BigInteger.valueOf(36);

  public static final BigInteger TWO = BigInteger.valueOf(2);

  private static final Cache<Hash, Address> senderCache =
      CacheBuilder.newBuilder().recordStats().maximumSize(100_000L).build();

  private final Optional<Short> dsaType;
  private final long nonce;

  private final Optional<Wei> gasPrice;

  private final Optional<Wei> maxPriorityFeePerGas;

  private final Optional<Wei> maxFeePerGas;
  private final Optional<Wei> maxFeePerBlobGas;

  private final long gasLimit;

  private final Optional<Address> to;

  private final Wei value;

  private final Signature signature;

  private final Payload payload;

  private final Optional<List<AccessListEntry>> maybeAccessList;

  private final Optional<BigInteger> chainId;

  // Caches a "hash" of a portion of the transaction used for sender recovery.
  // Note that this hash does not include the transaction signature, so it does not
  // fully identify the transaction (use the result of the {@code hash()} for that).
  // It is only used to compute said signature and recover the sender from it.
  private volatile Bytes32 hashNoSignature;

  // Caches the transaction sender.
  private volatile Address sender;

  // Caches the hash used to uniquely identify the transaction.
  private volatile Hash hash;
  // Caches the size in bytes of the encoded transaction.
  private volatile int sizeForAnnouncement = -1;
  private volatile int sizeForBlockInclusion = -1;
  private final TransactionType transactionType;

  private final Optional<PublicKey> providedPublicKey;
  private volatile PublicKey publicKey;
  // Why the signer could not be resolved, once that has been tried. The outcome depends only on
  // the signature, the hash and the algorithm, all fixed here, so it is not tried again: a peer
  // sending such transactions would otherwise make every lookup of their sender -- sorting a
  // batch, checking priority, validating, logging -- repeat the recovery.
  private volatile IllegalArgumentException unresolvableSigner;

  private final DigitalSignatureAlgorithm signatureAlgorithm;
  private final Optional<List<VersionedHash>> versionedHashes;

  private final Optional<BlobsWithCommitments> blobsWithCommitments;
  private final Optional<List<CodeDelegation>> maybeCodeDelegationList;

  private final Optional<Bytes> rawRlp;

  public static Builder builder() {
    return new Builder();
  }

  public static Transaction readFrom(final Bytes rlpBytes) {
    return readFrom(RLP.input(rlpBytes));
  }

  /**
   * Recreate a transaction from RLP serialized in the block body format
   *
   * @param rlpInput the RLP input in block body format
   * @return the transaction
   */
  public static Transaction readFrom(final RLPInput rlpInput) {
    return readFrom(rlpInput, EncodingContext.BLOCK_BODY);
  }

  /**
   * Recreate a transaction from RLP serialized according to the specified format
   *
   * @param rlpInput the RLP input in block body format
   * @param context specify in which format the RLP was serialized
   * @return the transaction
   */
  public static Transaction readFrom(final RLPInput rlpInput, final EncodingContext context) {
    return TransactionDecoder.decodeRLP(rlpInput, context);
  }

  /**
   * Instantiates a transaction instance.
   *
   * @param forCopy true when using to create a copy of an already validated transaction avoid to
   *     redo the validation
   * @param transactionType the transaction type
   * @param nonce the nonce
   * @param gasPrice the gas price
   * @param maxPriorityFeePerGas the max priority fee per gas
   * @param maxFeePerGas the max fee per gas
   * @param maxFeePerBlobGas the max fee per blob gas
   * @param gasLimit the gas limit
   * @param to the transaction recipient
   * @param value the value being transferred to the recipient
   * @param signature the signature
   * @param payload the payload
   * @param maybeAccessList the optional list of addresses/storage slots this transaction intends to
   *     preload
   * @param sender the transaction sender
   * @param chainId the chain id to apply the transaction to
   *     <p>The {@code to} will be an {@code Optional.empty()} for a contract creation transaction;
   *     otherwise it should contain an address.
   *     <p>The {@code chainId} must be greater than 0 to be applied to a specific chain; otherwise
   *     it will default to any chain.
   * @param hash the transaction hash
   * @param sizeForAnnouncement the size of the transaction, used for announcement
   * @param sizeForBlockInclusion the size of the transaction, used for block inclusion
   */
  private Transaction(
      final boolean forCopy,
      final TransactionType transactionType,
      final Optional<Short> dsaType,
      final long nonce,
      final Optional<Wei> gasPrice,
      final Optional<Wei> maxPriorityFeePerGas,
      final Optional<Wei> maxFeePerGas,
      final Optional<Wei> maxFeePerBlobGas,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Optional<PublicKey> pk,
      final Payload payload,
      final Signature signature,
      final Optional<List<AccessListEntry>> maybeAccessList,
      final Address sender,
      final Optional<BigInteger> chainId,
      final Optional<List<VersionedHash>> versionedHashes,
      final Optional<BlobsWithCommitments> blobsWithCommitments,
      final Optional<List<CodeDelegation>> maybeCodeDelegationList,
      final Optional<Bytes> rawRlp,
      final Optional<Hash> hash,
      final Optional<Integer> sizeForAnnouncement,
      final Optional<Integer> sizeForBlockInclusion) {

    if (!forCopy) {
      if (transactionType.requiresChainId()) {
        checkArgument(
            chainId.isPresent(),
            "Chain id must be present for transaction type %s",
            transactionType);
      }

      if (maybeAccessList.isPresent()) {
        checkArgument(
            transactionType.supportsAccessList(),
            "Must not specify access list for transaction not supporting it");
      }

      if (Objects.equals(transactionType, TransactionType.ACCESS_LIST)) {
        checkArgument(
            maybeAccessList.isPresent(), "Must specify access list for access list transaction");
      }

      if (versionedHashes.isPresent() || maxFeePerBlobGas.isPresent()) {
        checkArgument(
            transactionType.supportsBlob(),
            "Must not specify blob versioned hashes or max fee per blob gas for transaction not supporting it");
      }

      if (transactionType.supportsBlob()) {
        checkArgument(
            versionedHashes.isPresent(), "Must specify blob versioned hashes for blob transaction");
        checkArgument(
            !versionedHashes.get().isEmpty(),
            "Blob transaction must have at least one versioned hash");
        checkArgument(
            maxFeePerBlobGas.isPresent(), "Must specify max fee per blob gas for blob transaction");
      }

      if (transactionType.supportsDelegateCode()) {
        checkArgument(
            maybeCodeDelegationList.isPresent(),
            "Must specify code delegation authorizations for code delegation transaction");
      }
    }

    this.transactionType = transactionType;
    this.dsaType = dsaType;
    this.nonce = nonce;
    this.gasPrice = gasPrice;
    this.maxPriorityFeePerGas = maxPriorityFeePerGas;
    this.maxFeePerGas = maxFeePerGas;
    this.maxFeePerBlobGas = maxFeePerBlobGas;
    this.gasLimit = gasLimit;
    this.to = to;
    this.value = value;
    this.signature = signature;
    this.providedPublicKey = pk;
    this.payload = payload;
    this.maybeAccessList = maybeAccessList;
    this.sender = sender;
    this.chainId = chainId;
    this.versionedHashes = versionedHashes;
    this.blobsWithCommitments = blobsWithCommitments;
    this.maybeCodeDelegationList = maybeCodeDelegationList;
    this.rawRlp = rawRlp;
    hash.ifPresent(h -> this.hash = h);
    sizeForAnnouncement.ifPresent(i -> this.sizeForAnnouncement = i);
    sizeForBlockInclusion.ifPresent(i -> this.sizeForBlockInclusion = i);

    if(dsaType.isPresent()){
      this.signatureAlgorithm = DSAProviderFactory.getVerifierProvider().getAccountEnabledDSAById(dsaType.get());
    } else {
      this.signatureAlgorithm = SignatureAlgorithmFactory.getInstance();
    }
  }

  @Override
  public Optional<Short> getDsaType(){
    return dsaType;
  }

  /**
   * Whether any signature in this transaction is made with the network's curve, the genesis
   * ecCurve: its own when it carries no DSA type, or a code delegation's that carries none.
   *
   * @return true if the transaction or one of its code delegations has no DSA type
   */
  public boolean isSignedWithNetworkCurve() {
    return dsaType.isEmpty()
        || maybeCodeDelegationList
            .map(delegations -> delegations.stream().anyMatch(d -> d.dsaType().isEmpty()))
            .orElse(false);
  }

  @Override
  public PublicKey getMountedPublicKey(){
    if(publicKey == null){
      if (unresolvableSigner != null) {
        throw unresolvableSigner;
      }
      try {
        // The handler records the recovery, when there is one, in the PKR metrics. A key that
        // travelled with the transaction is not recovered, so it is not recorded.
        publicKey = PublicKeyHandler.resolvePublicKey(
          signatureAlgorithm,
          signature,
          providedPublicKey,
          getOrComputeSenderRecoveryHash(),
          "tx"
        ).get();
      } catch (final IllegalArgumentException e) {
        unresolvableSigner = e;
        throw e;
      }
    }
    return publicKey;
  }

  @Override
  public Optional<PublicKey> getMaybePublicKey(){
    return providedPublicKey;
  }
  /**
   * Returns the transaction nonce.
   *
   * @return the transaction nonce
   */
  @Override
  public long getNonce() {
    return nonce;
  }

  /**
   * Return the transaction gas price.
   *
   * @return the transaction gas price
   */
  @Override
  public Optional<Wei> getGasPrice() {
    return gasPrice;
  }

  /**
   * Return the transaction max priority per gas.
   *
   * @return the transaction max priority per gas
   */
  @Override
  public Optional<Wei> getMaxPriorityFeePerGas() {
    return maxPriorityFeePerGas;
  }

  /**
   * Return the transaction max fee per gas.
   *
   * @return the transaction max fee per gas
   */
  @Override
  public Optional<Wei> getMaxFeePerGas() {
    return maxFeePerGas;
  }

  /**
   * Return the transaction max fee per blob gas.
   *
   * @return the transaction max fee per blob gas
   */
  @Override
  public Optional<Wei> getMaxFeePerBlobGas() {
    return maxFeePerBlobGas;
  }

  /**
   * Return the effective priority fee per gas for this transaction.
   *
   * @param maybeBaseFee base fee in case of EIP-1559 transaction
   * @return priority fee per gas in wei
   */
  public Wei getEffectivePriorityFeePerGas(final Optional<Wei> maybeBaseFee) {
    return maybeBaseFee
        .map(
            baseFee -> {
              if (getType().supports1559FeeMarket()) {
                if (baseFee.greaterOrEqualThan(getMaxFeePerGas().get())) {
                  return Wei.ZERO;
                }
                return UInt256s.min(
                    getMaxPriorityFeePerGas().get(), getMaxFeePerGas().get().subtract(baseFee));
              } else {
                if (baseFee.greaterOrEqualThan(getGasPrice().get())) {
                  return Wei.ZERO;
                }
                return getGasPrice().get().subtract(baseFee);
              }
            })
        .orElseGet(() -> getGasPrice().orElse(Wei.ZERO));
  }

  /**
   * Returns the transaction gas limit.
   *
   * @return the transaction gas limit
   */
  @Override
  public long getGasLimit() {
    return gasLimit;
  }

  /**
   * Returns the number of blobs this transaction has, or 0 if not a blob transaction type
   *
   * @return return the count
   */
  public int getBlobCount() {
    return versionedHashes.map(List::size).orElse(0);
  }

  /**
   * Returns the transaction recipient.
   *
   * <p>The {@code Optional<Address>} will be {@code Optional.empty()} if the transaction is a
   * contract creation; otherwise it will contain the message call transaction recipient.
   *
   * @return the transaction recipient if a message call; otherwise {@code Optional.empty()}
   */
  @Override
  public Optional<Address> getTo() {
    return to;
  }

  /**
   * Returns the value transferred in the transaction.
   *
   * @return the value transferred in the transaction
   */
  @Override
  public Wei getValue() {
    return value;
  }

  /**
   * Returns the signature used to sign the transaction.
   *
   * @return the signature used to sign the transaction
   */
  @Override
  public Signature getSignature() {
    return signature;
  }

  /**
   * Returns the transaction payload.
   *
   * @return the transaction payload
   */
  @Override
  public Bytes getPayload() {
    return payload.getPayloadBytes();
  }

  @Override
  public long getPayloadZeroBytes() {
    return payload.getZeroBytesCount();
  }

  /**
   * Returns the payload if this is a contract creation transaction.
   *
   * @return if present the init code
   */
  @Override
  public Optional<Bytes> getInit() {
    return getTo().isPresent() ? Optional.empty() : Optional.of(payload.getPayloadBytes());
  }

  /**
   * Returns the payload if this is a message call transaction.
   *
   * @return if present the init code
   */
  @Override
  public Optional<Bytes> getData() {
    return getTo().isPresent() ? Optional.of(payload.getPayloadBytes()) : Optional.empty();
  }

  @Override
  public Optional<List<AccessListEntry>> getAccessList() {
    return maybeAccessList;
  }

  /**
   * Return the transaction chain id (if it exists)
   *
   * <p>The {@code OptionalInt} will be {@code OptionalInt.empty()} if the transaction is not tied
   * to a specific chain.
   *
   * @return the transaction chain id if it exists; otherwise {@code OptionalInt.empty()}
   */
  @Override
  public Optional<BigInteger> getChainId() {
    return chainId;
  }

  /**
   * Returns the transaction sender.
   *
   * @return the transaction sender
   */
  @Override
  public Address getSender() {
    if (sender == null) {
      // The cache is consulted before the key is resolved: the hash covers every byte the key is
      // resolved from, so a transaction whose sender is cached resolves to that same sender, and
      // each decoded copy of it -- from gossip, a proposal, a block -- would otherwise repeat the
      // recovery. The key is still resolved on demand wherever it is needed itself.
      final Address cachedSender = senderCache.getIfPresent(getHash());
      if (cachedSender != null) {
        sender = cachedSender;
      } else {
        publicKey = getMountedPublicKey();
        sender = computeSender();
      }
    }
    
    return sender;
  }

  /**
   * The sender, or empty when the signature cannot be attributed to anyone: no public key can be
   * recovered from it, or a non-recoverable algorithm carries none. Such a transaction is invalid,
   * which validation reports; this lets code that runs before it -- sorting, pre-computing senders,
   * logging -- leave the transaction to be rejected there. The recovery is attempted only once.
   *
   * <p>Static, and built on {@link #getSender()}, so that a mocked transaction whose sender is
   * stubbed still has one.
   *
   * @param transaction the transaction
   * @return the sender, if it can be determined
   */
  public static Optional<Address> resolvableSender(final Transaction transaction) {
    try {
      return Optional.of(transaction.getSender());
    } catch (final IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  private String senderForLogs() {
    return resolvableSender(this).map(Address::toString).orElse("unknown");
  }

  private Address computeSender() {
    final Address calculatedSender =
        Address.extract(Bytes32.wrap(Hash.hash(Bytes.wrap(publicKey.getEncoded())).getBytes()));
    senderCache.put(getHash(), calculatedSender);
    return calculatedSender;
  }

  /**
   * Returns the public key extracted from the signature.
   *
   * @return the public key
   */
  public Optional<String> getPublicKey() {
    return Optional.ofNullable(Bytes.wrap(getMountedPublicKey().getEncoded()).toHexString());
  }
  
  public Bytes32 getSigningHash(){
    return getOrComputeSenderRecoveryHash();
  }

  private Bytes32 getOrComputeSenderRecoveryHash() {
    if (hashNoSignature == null) {
      hashNoSignature =
          computeSenderRecoveryHash(
              transactionType,
              dsaType,
              nonce,
              gasPrice.orElse(null),
              maxPriorityFeePerGas.orElse(null),
              maxFeePerGas.orElse(null),
              maxFeePerBlobGas.orElse(null),
              gasLimit,
              to,
              value,
              providedPublicKey,
              payload,
              maybeAccessList,
              versionedHashes.orElse(null),
              maybeCodeDelegationList,
              chainId);
    }
    return hashNoSignature;
  }

  /**
   * Writes the transaction to RLP using the block body format
   *
   * @param out the output to write the transaction to
   */
  public void writeTo(final RLPOutput out) {
    writeTo(out, EncodingContext.BLOCK_BODY);
  }

  /**
   * Writes the transaction to RLP using the specified format
   *
   * @param out the output to write the transaction to
   * @param context the serialization format to use
   */
  public void writeTo(final RLPOutput out, final EncodingContext context) {
    TransactionEncoder.encodeRLP(this, out, context);
  }

  @Override
  public Bytes encoded() {
    final BytesValueRLPOutput rplOutput = new BytesValueRLPOutput();
    writeTo(rplOutput);
    return rplOutput.encoded();
  }

  @Override
  public BigInteger getR() {
    if (signature instanceof SECPSignature ecdsa) {
      return ecdsa.getR();
    }
    return null;
  }

  @Override
  public BigInteger getS() {
    if (signature instanceof SECPSignature ecdsa) {
      return ecdsa.getS();
    }
    return null;
  }

  @Override
  public BigInteger getV() {
    if (transactionType != null && transactionType != TransactionType.FRONTIER) {
      // EIP-2718 typed transaction, use yParity:
      return null;
    } else if (signature instanceof SECPSignature ecdsa) {
      final BigInteger recId = BigInteger.valueOf(ecdsa.getRecId());

      return chainId
          .map(bigInteger -> recId.add(REPLAY_PROTECTED_V_BASE).add(TWO.multiply(bigInteger)))
          .orElseGet(() -> recId.add(REPLAY_UNPROTECTED_V_BASE));
    }

    return null;
  }

  @Override
  public BigInteger getYParity() {
    if (transactionType != null && transactionType != TransactionType.FRONTIER) {
      // EIP-2718 typed transaction, return yParity:
      if(signature instanceof SECPSignature ecdsa){
        return BigInteger.valueOf(ecdsa.getRecId());
      }
      return null;
    } else {
      // legacy types never return yParity
      return null;
    }
  }

  /**
   * Returns the transaction hash.
   *
   * @return the transaction hash
   */
  @Override
  public Hash getHash() {
    if (hash == null) {
      memoizeHashAndSizeForBlockInclusion();
    }
    return hash;
  }

  /**
   * Returns the size in bytes of the encoded transaction.
   *
   * @return the size in bytes of the encoded transaction.
   */
  @Override
  public int getSizeForAnnouncement() {
    if (sizeForAnnouncement == -1) {
      memoizeSizeForAnnouncement();
    }
    return sizeForAnnouncement;
  }

  /**
   * Returns the size in bytes of the encoded transaction for block inclusion.
   *
   * @return the size in bytes of the encoded transaction for block inclusion.
   */
  @Override
  public int getSizeForBlockInclusion() {
    if (sizeForBlockInclusion == -1) {
      memoizeHashAndSizeForBlockInclusion();
    }
    return sizeForBlockInclusion;
  }

  private void memoizeHashAndSizeForBlockInclusion() {
    final Bytes bytes = TransactionEncoder.encodeOpaqueBytes(this, EncodingContext.BLOCK_BODY);
    hash = Hash.hash(bytes);
    sizeForBlockInclusion = bytes.size();
    if (!transactionType.supportsBlob() || this.getBlobsWithCommitments().isEmpty()) {
      // for transactions not containing blobs the encoding is the same, so we can set this as well:
      sizeForAnnouncement = sizeForBlockInclusion;
    }
  }

  private void memoizeSizeForAnnouncement() {
    final Bytes pooledBytes =
        TransactionEncoder.encodeOpaqueBytes(this, EncodingContext.POOLED_TRANSACTION);
    sizeForAnnouncement = pooledBytes.size();
    if (!transactionType.supportsBlob() || this.getBlobsWithCommitments().isEmpty()) {
      // for transactions not containing blobs the encoding is the same, so we can set these as
      // well:
      sizeForBlockInclusion = sizeForAnnouncement;
      if (hash == null) {
        hash = Hash.hash(pooledBytes);
      }
    }
  }

  @Override
  public boolean isContractCreation() {
    return getTo().isEmpty();
  }

  /**
   * Calculates the max up-front cost for the gas the transaction can use.
   *
   * @return the max up-front cost for the gas the transaction can use.
   */
  private Wei getMaxUpfrontGasCost(final long blobGasPerBlock) {
    return getUpfrontGasCost(
        getMaxGasPrice(), getMaxFeePerBlobGas().orElse(Wei.ZERO), blobGasPerBlock);
  }

  /**
   * Calculates the up-front cost for the gas and blob gas the transaction can use.
   *
   * @param gasPrice the gas price to use
   * @param blobGasPrice the blob gas price to use
   * @return the up-front cost for the gas the transaction can use.
   */
  public Wei getUpfrontGasCost(
      final Wei gasPrice, final Wei blobGasPrice, final long totalBlobGas) {
    if (gasPrice == null || gasPrice.isZero()) {
      return Wei.ZERO;
    }

    final var cost = calculateUpfrontGasCost(gasPrice, blobGasPrice, totalBlobGas);

    if (cost.bitLength() > 256) {
      return Wei.MAX_WEI;
    } else {
      return Wei.of(cost);
    }
  }

  public BigInteger calculateUpfrontGasCost(
      final Wei gasPrice, final Wei blobGasPrice, final long totalBlobGas) {
    var cost =
        new BigInteger(1, Longs.toByteArray(getGasLimit())).multiply(gasPrice.getAsBigInteger());

    if (transactionType.supportsBlob()) {
      cost = cost.add(blobGasPrice.getAsBigInteger().multiply(BigInteger.valueOf(totalBlobGas)));
    }

    return cost;
  }

  /**
   * Calculates the up-front cost for the transaction.
   *
   * <p>The up-front cost is paid by the sender account before the transaction is executed. The
   * sender must have the amount in its account balance to execute and some of this amount may be
   * refunded after the transaction has executed.
   *
   * @return the up-front gas cost for the transaction
   */
  public Wei getUpfrontCost(final long totalBlobGas) {
    Wei maxUpfrontGasCost = getMaxUpfrontGasCost(totalBlobGas);
    Wei result = maxUpfrontGasCost.add(getValue());
    return (maxUpfrontGasCost.compareTo(result) > 0) ? Wei.MAX_WEI : result;
  }

  /**
   * Return the maximum fee per gas the sender is willing to pay for this transaction.
   *
   * @return max fee per gas in wei
   */
  public Wei getMaxGasPrice() {
    return maxFeePerGas.orElseGet(
        () ->
            gasPrice.orElseThrow(
                () ->
                    new IllegalStateException(
                        "Transaction requires either gasPrice or maxFeePerGas")));
  }

  /**
   * Calculates the effectiveGasPrice of a transaction on the basis of an {@code Optional<Long>}
   * baseFee and handles unwrapping Optional fee parameters. If baseFee is present, effective gas is
   * calculated as:
   *
   * <p>min((baseFeePerGas + maxPriorityFeePerGas), maxFeePerGas)
   *
   * <p>Otherwise, return gasPrice for legacy transactions.
   *
   * @param baseFeePerGas optional baseFee from the block header, if we are post-london
   * @return the effective gas price.
   */
  public final Wei getEffectiveGasPrice(final Optional<Wei> baseFeePerGas) {
    return getEffectivePriorityFeePerGas(baseFeePerGas).addExact(baseFeePerGas.orElse(Wei.ZERO));
  }

  public Optional<Bytes> getRawRlp() {
    return rawRlp;
  }

  @Override
  public TransactionType getType() {
    return this.transactionType;
  }

  @Override
  public Optional<List<VersionedHash>> getVersionedHashes() {
    return versionedHashes;
  }

  @Override
  public Optional<BlobsWithCommitments> getBlobsWithCommitments() {
    return blobsWithCommitments;
  }

  @Override
  public Optional<List<CodeDelegation>> getCodeDelegationList() {
    return maybeCodeDelegationList;
  }

  @Override
  public int codeDelegationListSize() {
    return maybeCodeDelegationList.map(List::size).orElse(0);
  }

  /**
   * Return the list of transaction hashes extracted from the collection of Transaction passed as
   * argument
   *
   * @param transactions a collection of transactions
   * @return the list of transaction hashes
   */
  public static List<Hash> toHashList(final Collection<Transaction> transactions) {
    return transactions.stream().map(Transaction::getHash).toList();
  }

  private static Bytes32 computeSenderRecoveryHash(
      final TransactionType transactionType,
      final Optional<Short> dsaType,
      final long nonce,
      final Wei gasPrice,
      final Wei maxPriorityFeePerGas,
      final Wei maxFeePerGas,
      final Wei maxFeePerBlobGas,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Optional<PublicKey> pk,
      final Payload payload,
      final Optional<List<AccessListEntry>> accessList,
      final List<VersionedHash> versionedHashes,
      final Optional<List<CodeDelegation>> codeDelegationList,
      final Optional<BigInteger> chainId) {
    if (transactionType.requiresChainId()) {
      checkArgument(chainId.isPresent(), "Transaction type %s requires chainId", transactionType);
    }
    final Bytes preimage =
        getPreimage(
            transactionType,
            dsaType,
            nonce,
            gasPrice,
            maxPriorityFeePerGas,
            maxFeePerGas,
            maxFeePerBlobGas,
            gasLimit,
            to,
            value,
            pk,
            payload.getPayloadBytes(),
            accessList,
            versionedHashes,
            codeDelegationList,
            chainId);
    return keccak256(preimage);
  }

  @Override
  public Bytes encodedPreimage() {
    return getPreimage(
        transactionType,
        dsaType,
        nonce,
        gasPrice.orElse(null),
        maxPriorityFeePerGas.orElse(null),
        maxFeePerGas.orElse(null),
        maxFeePerBlobGas.orElse(null),
        gasLimit,
        to,
        value,
        providedPublicKey,
        payload.getPayloadBytes(),
        maybeAccessList,
        versionedHashes.orElse(null),
        maybeCodeDelegationList,
        chainId);
  }

  private static Bytes getPreimage(
      final TransactionType transactionType,
      final Optional<Short> dsaType,
      final long nonce,
      final Wei gasPrice,
      final Wei maxPriorityFeePerGas,
      final Wei maxFeePerGas,
      final Wei maxFeePerBlobGas,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Optional<PublicKey> providedPublicKey,
      final Bytes payload,
      final Optional<List<AccessListEntry>> accessList,
      final List<VersionedHash> versionedHashes,
      final Optional<List<CodeDelegation>> codeDelegationList,
      final Optional<BigInteger> chainId) {
    final Bytes preimage =
        switch (transactionType) {
          case FRONTIER -> frontierPreimage(nonce, gasPrice, gasLimit, to, value, payload, chainId);
          case EIP1559 ->
              eip1559Preimage(
                  nonce,
                  maxPriorityFeePerGas,
                  maxFeePerGas,
                  gasLimit,
                  to,
                  value,
                  payload,
                  chainId,
                  accessList);
          case BLOB ->
              blobPreimage(
                  nonce,
                  maxPriorityFeePerGas,
                  maxFeePerGas,
                  maxFeePerBlobGas,
                  gasLimit,
                  to,
                  value,
                  payload,
                  chainId,
                  accessList,
                  versionedHashes);
          case ACCESS_LIST ->
              accessListPreimage(
                  nonce,
                  gasPrice,
                  gasLimit,
                  to,
                  value,
                  payload,
                  accessList.orElseThrow(
                      () ->
                          new IllegalStateException(
                              "Developer error: the transaction should be guaranteed to have an access list here")),
                  chainId);
          case DELEGATE_CODE ->
              codeDelegationPreimage(
                  nonce,
                  maxPriorityFeePerGas,
                  maxFeePerGas,
                  gasLimit,
                  to,
                  value,
                  payload,
                  chainId,
                  accessList,
                  codeDelegationList.orElseThrow(
                      () ->
                          new IllegalStateException(
                              "Developer error: the transaction should be guaranteed to have a code delegations here")));
          case FLEXIBLE_ACCESS_LIST -> 
              flexibleAccessListPreimage(
                dsaType,
                nonce,
                gasPrice,
                gasLimit,
                to,
                value,
                providedPublicKey,
                payload,
                accessList.orElseThrow(
                    () ->
                        new IllegalStateException(
                            "Developer error: the transaction should be guaranteed to have an access list here")),
                chainId);
          case FLEXIBLE_EIP1559 -> 
              flexibleEip1559Preimage(
                dsaType,
                nonce,
                maxPriorityFeePerGas,
                maxFeePerGas,
                gasLimit,
                to,
                value,
                providedPublicKey,
                payload,
                accessList,
                chainId);
          case FLEXIBLE_BLOB -> 
              flexibleBlobPreimage(
                dsaType,
                nonce,
                maxPriorityFeePerGas,
                maxFeePerGas,
                maxFeePerBlobGas,
                gasLimit,
                to,
                value,
                providedPublicKey,
                payload,
                chainId,
                accessList,
                versionedHashes);
          case FLEXIBLE_DELEGATE_CODE ->
              flexibleCodeDelegationPreimage(
                  dsaType,
                  nonce,
                  maxPriorityFeePerGas,
                  maxFeePerGas,
                  gasLimit,
                  to,
                  value,
                  providedPublicKey,
                  payload,
                  chainId,
                  accessList,
                  codeDelegationList.orElseThrow(
                      () ->
                          new IllegalStateException(
                              "Developer error: the transaction should be guaranteed to have a code delegations here")));
          default -> throw new IllegalArgumentException("Unexpected value: " + transactionType);
        };
    return preimage;
  }

  private static Bytes frontierPreimage(
      final long nonce,
      final Wei gasPrice,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Bytes payload,
      final Optional<BigInteger> chainId) {
    return RLP.encode(
        rlpOutput -> {
          rlpOutput.startList();
          rlpOutput.writeLongScalar(nonce);
          rlpOutput.writeUInt256Scalar(gasPrice);
          rlpOutput.writeLongScalar(gasLimit);
          rlpOutput.writeBytes(to.map(BytesHolder::getBytes).map(Bytes::copy).orElse(Bytes.EMPTY));
          rlpOutput.writeUInt256Scalar(value);
          rlpOutput.writeBytes(payload);
          if (chainId.isPresent()) {
            rlpOutput.writeBigIntegerScalar(chainId.get());
            rlpOutput.writeUInt256Scalar(UInt256.ZERO);
            rlpOutput.writeUInt256Scalar(UInt256.ZERO);
          }
          rlpOutput.endList();
        });
  }

  private static Bytes eip1559Preimage(
      final long nonce,
      final Wei maxPriorityFeePerGas,
      final Wei maxFeePerGas,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Bytes payload,
      final Optional<BigInteger> chainId,
      final Optional<List<AccessListEntry>> accessList) {
    final Bytes encoded =
        RLP.encode(
            rlpOutput -> {
              rlpOutput.startList();
              eip1559PreimageFields(
                  nonce,
                  maxPriorityFeePerGas,
                  maxFeePerGas,
                  gasLimit,
                  to,
                  value,
                  payload,
                  chainId,
                  accessList,
                  rlpOutput);
              rlpOutput.endList();
            });
    return Bytes.concatenate(Bytes.of(TransactionType.EIP1559.getSerializedType()), encoded);
  }

  private static Bytes flexibleEip1559Preimage(
    final Optional<Short> dsaType,
    final long nonce,
    final Wei maxPriorityFeePerGas,
    final Wei maxFeePerGas,
    final long gasLimit,
    final Optional<Address> to,
    final Wei value,
    final Optional<PublicKey> pk,
    final Bytes payload,
    final Optional<List<AccessListEntry>> accessList,
    final Optional<BigInteger> chainId
  ){
    final Bytes encoded = 
        RLP.encode(rlpOutput -> {
          rlpOutput.startList();
          rlpOutput.writeShort(dsaType.get());
          eip1559PreimageFields(
                  nonce,
                  maxPriorityFeePerGas,
                  maxFeePerGas,
                  gasLimit,
                  to,
                  value,
                  payload,
                  chainId,
                  accessList,
                  rlpOutput);
          // Only a transaction whose key cannot be recovered carries one to commit to.
          pk.ifPresent(publicKey -> rlpOutput.writeBytes(Bytes.wrap(publicKey.getEncoded())));
          rlpOutput.endList();
        });
    return Bytes.concatenate(Bytes.of(TransactionType.FLEXIBLE_EIP1559.getSerializedType()), encoded);
  }

  private static void eip1559PreimageFields(
      final long nonce,
      final Wei maxPriorityFeePerGas,
      final Wei maxFeePerGas,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Bytes payload,
      final Optional<BigInteger> chainId,
      final Optional<List<AccessListEntry>> accessList,
      final RLPOutput rlpOutput) {
    rlpOutput.writeBigIntegerScalar(chainId.orElseThrow());
    rlpOutput.writeLongScalar(nonce);
    rlpOutput.writeUInt256Scalar(maxPriorityFeePerGas);
    rlpOutput.writeUInt256Scalar(maxFeePerGas);
    rlpOutput.writeLongScalar(gasLimit);
    rlpOutput.writeBytes(to.map(BytesHolder::getBytes).map(Bytes::copy).orElse(Bytes.EMPTY));
    rlpOutput.writeUInt256Scalar(value);
    rlpOutput.writeBytes(payload);
    AccessListTransactionEncoder.writeAccessList(rlpOutput, accessList);
  }

  private static Bytes blobPreimage(
      final long nonce,
      final Wei maxPriorityFeePerGas,
      final Wei maxFeePerGas,
      final Wei maxFeePerBlobGas,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Bytes payload,
      final Optional<BigInteger> chainId,
      final Optional<List<AccessListEntry>> accessList,
      final List<VersionedHash> versionedHashes) {

    final Bytes encoded =
        RLP.encode(
            rlpOutput -> {
              rlpOutput.startList();
              eip1559PreimageFields(
                  nonce,
                  maxPriorityFeePerGas,
                  maxFeePerGas,
                  gasLimit,
                  to,
                  value,
                  payload,
                  chainId,
                  accessList,
                  rlpOutput);
              rlpOutput.writeUInt256Scalar(maxFeePerBlobGas);
              BlobTransactionEncoder.writeBlobVersionedHashes(rlpOutput, versionedHashes);
              rlpOutput.endList();
            });
    return Bytes.concatenate(Bytes.of(TransactionType.BLOB.getSerializedType()), encoded);
  }

  private static Bytes flexibleBlobPreimage(
      final Optional<Short> dsaType,
      final long nonce,
      final Wei maxPriorityFeePerGas,
      final Wei maxFeePerGas,
      final Wei maxFeePerBlobGas,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Optional<PublicKey> pk,
      final Bytes payload,
      final Optional<BigInteger> chainId,
      final Optional<List<AccessListEntry>> accessList,
      final List<VersionedHash> versionedHashes
  ){
    final Bytes encoded = 
        RLP.encode(
          rlpOutput -> {
            rlpOutput.startList();
            rlpOutput.writeShort(dsaType.get());
            eip1559PreimageFields(
                  nonce,
                  maxPriorityFeePerGas,
                  maxFeePerGas,
                  gasLimit,
                  to,
                  value,
                  payload,
                  chainId,
                  accessList,
                  rlpOutput);
            rlpOutput.writeUInt256Scalar(maxFeePerBlobGas);
            BlobTransactionEncoder.writeBlobVersionedHashes(rlpOutput, versionedHashes);
            // Only a transaction whose key cannot be recovered carries one to commit to.
            pk.ifPresent(publicKey -> rlpOutput.writeBytes(Bytes.wrap(publicKey.getEncoded())));
            rlpOutput.endList();
          }
        );
    return Bytes.concatenate(Bytes.of(TransactionType.FLEXIBLE_BLOB.getSerializedType()), encoded);
  }

  private static Bytes accessListPreimage(
      final long nonce,
      final Wei gasPrice,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Bytes payload,
      final List<AccessListEntry> accessList,
      final Optional<BigInteger> chainId) {
    final Bytes encode =
        RLP.encode(
            rlpOutput -> {
              rlpOutput.startList();
              AccessListTransactionEncoder.encodeAccessListInner(
                  chainId, nonce, gasPrice, gasLimit, to, value, payload, accessList, rlpOutput);
              rlpOutput.endList();
            });
    return Bytes.concatenate(Bytes.of(TransactionType.ACCESS_LIST.getSerializedType()), encode);
  }

  private static Bytes flexibleAccessListPreimage(
      final Optional<Short> dsaType,
      final long nonce,
      final Wei gasPrice,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Optional<PublicKey> pk,
      final Bytes payload,
      final List<AccessListEntry> accessList,
      final Optional<BigInteger> chainId){
    final Bytes encoded = 
      RLP.encode(
        rlpOutput -> {
          rlpOutput.startList();
          FlexibleAccessListTransactionEncoder.encodeAccessListInner(
            dsaType,
            chainId,
            nonce,
            gasPrice,
            gasLimit,
            to,
            value,
            pk,
            payload,
            accessList,
            rlpOutput
          );
          rlpOutput.endList();
        }
      );
    return Bytes.concatenate(Bytes.of(TransactionType.FLEXIBLE_ACCESS_LIST.getSerializedType()), encoded);
  }

  private static Bytes codeDelegationPreimage(
      final long nonce,
      final Wei maxPriorityFeePerGas,
      final Wei maxFeePerGas,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Bytes payload,
      final Optional<BigInteger> chainId,
      final Optional<List<AccessListEntry>> accessList,
      final List<CodeDelegation> authorizationList) {
    final Bytes encoded =
        RLP.encode(
            rlpOutput -> {
              rlpOutput.startList();
              eip1559PreimageFields(
                  nonce,
                  maxPriorityFeePerGas,
                  maxFeePerGas,
                  gasLimit,
                  to,
                  value,
                  payload,
                  chainId,
                  accessList,
                  rlpOutput);
              CodeDelegationEncoder.encodeCodeDelegationInner(
                  authorizationList, rlpOutput);
              rlpOutput.endList();
            });
    return Bytes.concatenate(Bytes.of(TransactionType.DELEGATE_CODE.getSerializedType()), encoded);
  }

  private static Bytes flexibleCodeDelegationPreimage(
      final Optional<Short> dsaType,
      final long nonce,
      final Wei maxPriorityFeePerGas,
      final Wei maxFeePerGas,
      final long gasLimit,
      final Optional<Address> to,
      final Wei value,
      final Optional<PublicKey> providedPublicKey,
      final Bytes payload,
      final Optional<BigInteger> chainId,
      final Optional<List<AccessListEntry>> accessList,
      final List<CodeDelegation> authorizationList) {
    final Bytes encoded =
        RLP.encode(
            rlpOutput -> {
              rlpOutput.startList();
              rlpOutput.writeShort(dsaType.get());
              eip1559PreimageFields(
                  nonce,
                  maxPriorityFeePerGas,
                  maxFeePerGas,
                  gasLimit,
                  to,
                  value,
                  payload,
                  chainId,
                  accessList,
                  rlpOutput);
              CodeDelegationEncoder.encodeCodeDelegationInner(
                  authorizationList, rlpOutput);
                  
              // Only a transaction whose key cannot be recovered carries one to commit to.
              providedPublicKey.ifPresent(
                  publicKey -> rlpOutput.writeBytes(Bytes.wrap(publicKey.getEncoded())));
              rlpOutput.endList();
            });
    return Bytes.concatenate(Bytes.of(TransactionType.FLEXIBLE_DELEGATE_CODE.getSerializedType()), encoded);
  }

  @Override
  public boolean equals(final Object other) {
    if (!(other instanceof Transaction that)) {
      return false;
    }
    return Objects.equals(this.chainId, that.chainId)
        && this.gasLimit == that.gasLimit
        && Objects.equals(this.gasPrice, that.gasPrice)
        && Objects.equals(this.maxPriorityFeePerGas, that.maxPriorityFeePerGas)
        && Objects.equals(this.maxFeePerGas, that.maxFeePerGas)
        && Objects.equals(this.maxFeePerBlobGas, that.maxFeePerBlobGas)
        && this.nonce == that.nonce
        && Objects.equals(this.payload, that.payload)
        && Objects.equals(this.signature, that.signature)
        && Objects.equals(this.to, that.to)
        && Objects.equals(this.value, that.value)
        && Objects.equals(this.getV(), that.getV());
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        nonce,
        gasPrice,
        maxPriorityFeePerGas,
        maxFeePerGas,
        maxFeePerBlobGas,
        gasLimit,
        to,
        value,
        payload.getPayloadBytes(),
        signature,
        chainId);
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder();
    sb.append(
            transactionType.supportsBlob()
                ? "Blob"
                : isContractCreation() ? "ContractCreation" : "MessageCall")
        .append("{");
    sb.append("type=").append(getType()).append(", ");
    // Invalid transactions are logged too, including one whose sender cannot be determined.
    sb.append("sender=").append(senderForLogs()).append(", ");
    sb.append("nonce=").append(getNonce()).append(", ");
    getGasPrice()
        .ifPresent(gp -> sb.append("gasPrice=").append(gp.toHumanReadableString()).append(", "));
    if (getMaxPriorityFeePerGas().isPresent() && getMaxFeePerGas().isPresent()) {
      sb.append("maxPriorityFeePerGas=")
          .append(getMaxPriorityFeePerGas().map(Wei::toHumanReadableString).get())
          .append(", ");
      sb.append("maxFeePerGas=")
          .append(getMaxFeePerGas().map(Wei::toHumanReadableString).get())
          .append(", ");
      getMaxFeePerBlobGas()
          .ifPresent(
              wei ->
                  sb.append("maxFeePerBlobGas=").append(wei.toHumanReadableString()).append(", "));
    }
    sb.append("gasLimit=").append(getGasLimit()).append(", ");
    if (getTo().isPresent()) sb.append("to=").append(getTo().get()).append(", ");
    sb.append("value=").append(getValue()).append(", ");
    sb.append("sig=").append(getSignature()).append(", ");
    if (chainId.isPresent()) sb.append("chainId=").append(getChainId().get()).append(", ");
    if (transactionType.equals(TransactionType.ACCESS_LIST)) {
      sb.append("accessList=").append(maybeAccessList).append(", ");
    }
    if (versionedHashes.isPresent()) {
      final List<VersionedHash> vhs = versionedHashes.get();
      if (!vhs.isEmpty()) {
        sb.append("versionedHashes=[");
        sb.append(
            vhs.get(0)
                .toString()); // can't be empty if present, as this is checked in the constructor
        for (int i = 1; i < vhs.size(); i++) {
          sb.append(", ").append(vhs.get(i).toString());
        }
        sb.append("], ");
      }
    }
    if (transactionType.supportsBlob() && this.blobsWithCommitments.isPresent()) {
      sb.append("numberOfBlobs=").append(blobsWithCommitments.get().getBlobs().size()).append(", ");
    }
    sb.append("dsaType=");
    if (dsaType.isPresent()) {
        sb.append(String.format("0x%04X", dsaType.get() & 0xFFFF)).append(", ");
    }
    sb.append("providedPublicKey=");
    if(getMaybePublicKey().isPresent()){
      sb.append(Bytes.wrap(getMaybePublicKey().get().getEncoded()).toHexString()).append(", ");
    }
    sb.append("signature=").append(getSignature().encodedBytes().toHexString()).append(", ");
    sb.append("payload=").append(getPayload());
    return sb.append("}").toString();
  }

  public String toTraceLog() {
    final StringBuilder sb = new StringBuilder();
    sb.append(getHash()).append("={");
    sb.append(
            transactionType.supportsBlob()
                ? "Blob"
                : isContractCreation() ? "ContractCreation" : "MessageCall")
        .append(", ");
    sb.append(getNonce()).append(", ");
    sb.append(senderForLogs()).append(", ");
    sb.append(getType()).append(", ");
    getGasPrice()
        .ifPresent(gp -> sb.append("gp: ").append(gp.toHumanReadableString()).append(", "));
    if (getMaxPriorityFeePerGas().isPresent() && getMaxFeePerGas().isPresent()) {
      sb.append("mf: ")
          .append(getMaxFeePerGas().map(Wei::toHumanReadableString).get())
          .append(", ");
      sb.append("pf: ")
          .append(getMaxPriorityFeePerGas().map(Wei::toHumanReadableString).get())
          .append(", ");
      getMaxFeePerBlobGas()
          .ifPresent(wei -> sb.append("df: ").append(wei.toHumanReadableString()).append(", "));
    }
    sb.append("gl: ").append(getGasLimit()).append(", ");
    sb.append("v: ").append(getValue().toHumanReadableString()).append(", ");
    getTo().ifPresent(t -> sb.append("to: ").append(t));
    return sb.append("}").toString();
  }

  @Override
  public Optional<Address> contractAddress() {
    if (isContractCreation()) {
      return Optional.of(Address.contractAddress(getSender(), getNonce()));
    }
    return Optional.empty();
  }

  /**
   * Creates a copy of this transaction that does not share any underlying byte array.
   *
   * <p>This is useful in case the transaction is built from a block body and fields, like to or
   * payload, are wrapping (and so keeping references) sections of the large RLP encoded block body,
   * and we plan to keep the transaction around for some time, like in the txpool in case of a
   * reorg, and do not want to keep all the block body in memory for a long time, but only the
   * actual transaction.
   *
   * @return a copy of the transaction
   */
  public Transaction detachedCopy() {
    final Optional<Address> detachedTo = to.map(address -> Address.wrap(address.getBytes().copy()));
    final Optional<List<AccessListEntry>> detachedAccessList =
        maybeAccessList.map(
            accessListEntries ->
                accessListEntries.stream().map(this::accessListDetachedCopy).toList());
    final Optional<List<VersionedHash>> detachedVersionedHashes =
        versionedHashes.map(
            hashes ->
                hashes.stream()
                    .map(vh -> new VersionedHash(Bytes32.wrap(vh.getBytes().copy())))
                    .toList());
    final Optional<BlobsWithCommitments> detachedBlobsWithCommitments =
        blobsWithCommitments.map(
            withCommitments ->
                blobsWithCommitmentsDetachedCopy(withCommitments, detachedVersionedHashes.get()));
    final Optional<List<CodeDelegation>> detachedCodeDelegationList =
        maybeCodeDelegationList.map(
            codeDelegations ->
                codeDelegations.stream().map(this::codeDelegationDetachedCopy).toList());

    final var copiedTx =
        new Transaction(
            true,
            transactionType,
            dsaType,
            nonce,
            gasPrice,
            maxPriorityFeePerGas,
            maxFeePerGas,
            maxFeePerBlobGas,
            gasLimit,
            detachedTo,
            value,
            providedPublicKey,
            payload,
            signature,
            detachedAccessList,
            sender,
            chainId,
            detachedVersionedHashes,
            detachedBlobsWithCommitments,
            detachedCodeDelegationList,
            Optional.empty(),
            Optional.ofNullable(hash),
            Optional.of(sizeForAnnouncement),
            Optional.of(sizeForBlockInclusion));

    // copy also the computed fields, to avoid to recompute them
    copiedTx.publicKey = this.publicKey;
    copiedTx.sender = this.sender;
    copiedTx.hashNoSignature = this.hashNoSignature;

    return copiedTx;
  }

  private AccessListEntry accessListDetachedCopy(final AccessListEntry accessListEntry) {
    final Address detachedAddress = Address.wrap(accessListEntry.address().getBytes().copy());
    final var detachedStorage = accessListEntry.storageKeys().stream().map(Bytes32::copy).toList();
    return new AccessListEntry(detachedAddress, detachedStorage);
  }

  private CodeDelegation codeDelegationDetachedCopy(final CodeDelegation codeDelegation) {
    final Address detachedAddress = Address.wrap(codeDelegation.address().getBytes().copy());
    // Every field is carried over: the legacy constructor would turn a flexible delegation into a
    // legacy one and drop its DSA type and public key.
    return new org.hyperledger.besu.ethereum.core.CodeDelegation(
        codeDelegation.getType(),
        codeDelegation.dsaType(),
        codeDelegation.chainId(),
        detachedAddress,
        codeDelegation.nonce(),
        codeDelegation.maybePublicKey(),
        codeDelegation.signature());
  }

  private BlobsWithCommitments blobsWithCommitmentsDetachedCopy(
      final BlobsWithCommitments blobsWithCommitments, final List<VersionedHash> versionedHashes) {
    final var detachedCommitments =
        blobsWithCommitments.getKzgCommitments().stream()
            .map(kc -> new KZGCommitment(kc.getData().copy()))
            .toList();
    final var detachedBlobs =
        blobsWithCommitments.getBlobs().stream()
            .map(blob -> new Blob(blob.getData().copy()))
            .toList();
    final var detachedProofs =
        blobsWithCommitments.getKzgProofs().stream()
            .map(proof -> new KZGProof(proof.getData().copy()))
            .toList();
    return new BlobsWithCommitments(
        blobsWithCommitments.getBlobType(),
        detachedCommitments,
        detachedBlobs,
        detachedProofs,
        versionedHashes);
  }

  public static class Builder {
    private static final Optional<List<AccessListEntry>> EMPTY_ACCESS_LIST = Optional.of(List.of());

    protected TransactionType transactionType;

    protected long nonce = -1L;

    protected Wei gasPrice;

    protected Wei maxPriorityFeePerGas;

    protected Wei maxFeePerGas;
    protected Wei maxFeePerBlobGas;

    protected long gasLimit = -1L;

    protected Optional<Address> to = Optional.empty();

    protected Wei value;

    protected Signature signature;

    protected Optional<PublicKey> providedPublicKey = Optional.empty();

    protected PublicKey publicKey = null;

    protected Payload payload;

    protected Optional<List<AccessListEntry>> accessList = Optional.empty();

    protected Address sender;

    protected Optional<Short> dsaType = Optional.empty();

    protected Optional<BigInteger> chainId = Optional.empty();
    protected Optional<BigInteger> v = Optional.empty();
    protected List<VersionedHash> versionedHashes = null;
    private BlobsWithCommitments blobsWithCommitments;
    protected Optional<List<CodeDelegation>> codeDelegationAuthorizations = Optional.empty();
    protected Bytes rawRlp = null;
    private Optional<Hash> hash = Optional.empty();
    private Optional<Integer> sizeForAnnouncement = Optional.empty();
    private Optional<Integer> sizeForBlockInclusion = Optional.empty();

    public Builder copiedFrom(final Transaction toCopy) {
      this.transactionType = toCopy.transactionType;
      this.nonce = toCopy.nonce;
      this.gasPrice = toCopy.gasPrice.orElse(null);
      this.maxPriorityFeePerGas = toCopy.maxPriorityFeePerGas.orElse(null);
      this.maxFeePerGas = toCopy.maxFeePerGas.orElse(null);
      this.maxFeePerBlobGas = toCopy.maxFeePerBlobGas.orElse(null);
      this.gasLimit = toCopy.gasLimit;
      this.to = toCopy.to;
      this.value = toCopy.value;
      this.signature = toCopy.signature;
      this.providedPublicKey = toCopy.providedPublicKey;
      this.publicKey = toCopy.publicKey;
      this.payload = toCopy.payload;
      this.accessList = toCopy.maybeAccessList;
      this.sender = toCopy.sender;
      this.dsaType = toCopy.dsaType;
      this.chainId = toCopy.chainId;
      this.versionedHashes = toCopy.versionedHashes.orElse(null);
      this.blobsWithCommitments = toCopy.blobsWithCommitments.orElse(null);
      this.codeDelegationAuthorizations = toCopy.maybeCodeDelegationList;
      return this;
    }

    public Builder type(final TransactionType transactionType) {
      this.transactionType = transactionType;
      return this;
    }

    public Builder dsaType(final Short dsaType){
      this.dsaType = Optional.of(dsaType);
      return this;
    }

    public Builder chainId(final BigInteger chainId) {
      this.chainId = Optional.of(chainId);
      return this;
    }

    public Builder v(final BigInteger v) {
      this.v = Optional.of(v);
      return this;
    }

    public Builder gasPrice(final Wei gasPrice) {
      this.gasPrice = gasPrice;
      return this;
    }

    public Builder maxPriorityFeePerGas(final Wei maxPriorityFeePerGas) {
      this.maxPriorityFeePerGas = maxPriorityFeePerGas;
      return this;
    }

    public Builder maxFeePerGas(final Wei maxFeePerGas) {
      this.maxFeePerGas = maxFeePerGas;
      return this;
    }

    public Builder maxFeePerBlobGas(final Wei maxFeePerBlobGas) {
      this.maxFeePerBlobGas = maxFeePerBlobGas;
      return this;
    }

    public Builder gasLimit(final long gasLimit) {
      this.gasLimit = gasLimit;
      return this;
    }

    public Builder nonce(final long nonce) {
      this.nonce = nonce;
      return this;
    }

    public Builder value(final Wei value) {
      this.value = value;
      return this;
    }

    public Builder to(final Address to) {
      this.to = Optional.ofNullable(to);
      return this;
    }

    public Builder payload(final Bytes payload) {
      this.payload = new Payload(payload);
      return this;
    }

    public Builder accessList(final List<AccessListEntry> accessList) {
      this.accessList =
          accessList == null
              ? Optional.empty()
              : accessList.isEmpty() ? EMPTY_ACCESS_LIST : Optional.of(accessList);
      return this;
    }

    public Builder sender(final Address sender) {
      this.sender = sender;
      return this;
    }

    public Builder signature(final Signature signature) {
      this.signature = signature;
      return this;
    }

    public Builder providedPublicKey(final Optional<PublicKey> providedPublicKey){
      this.providedPublicKey = providedPublicKey;
      return this;
    }

    public Builder publicKey(final PublicKey publicKey){
      this.publicKey = publicKey;
      return this;
    }

    public Builder versionedHashes(final List<VersionedHash> versionedHashes) {
      this.versionedHashes = versionedHashes;
      return this;
    }

    public Builder rawRlp(final Bytes rawRlp) {
      this.rawRlp = rawRlp;
      return this;
    }

    public Builder hash(final Hash hash) {
      this.hash = Optional.ofNullable(hash);
      return this;
    }

    public Builder sizeForAnnouncement(final int sizeForAnnouncement) {
      this.sizeForAnnouncement = Optional.of(sizeForAnnouncement);
      return this;
    }

    public Builder sizeForBlockInclusion(final int sizeForBlockInclusion) {
      this.sizeForBlockInclusion = Optional.of(sizeForBlockInclusion);
      return this;
    }

    public Builder guessType() {
      if (codeDelegationAuthorizations.isPresent()) {
        transactionType = TransactionType.DELEGATE_CODE;
      } else if (versionedHashes != null && !versionedHashes.isEmpty()) {
        transactionType = TransactionType.BLOB;
      } else if (maxPriorityFeePerGas != null || maxFeePerGas != null) {
        transactionType = TransactionType.EIP1559;
      } else if (accessList.isPresent()) {
        transactionType = TransactionType.ACCESS_LIST;
      } else {
        transactionType = TransactionType.FRONTIER;
      }
      return this;
    }

    public TransactionType getTransactionType() {
      return transactionType;
    }

    public Transaction build() {
      if (transactionType == null) guessType();
      return new Transaction(
          false,
          transactionType,
          dsaType,
          nonce,
          Optional.ofNullable(gasPrice),
          Optional.ofNullable(maxPriorityFeePerGas),
          Optional.ofNullable(maxFeePerGas),
          Optional.ofNullable(maxFeePerBlobGas),
          gasLimit,
          to,
          value,
          providedPublicKey,
          payload,
          signature,
          accessList,
          sender,
          chainId,
          Optional.ofNullable(versionedHashes),
          Optional.ofNullable(blobsWithCommitments),
          codeDelegationAuthorizations,
          Optional.ofNullable(rawRlp),
          hash,
          sizeForAnnouncement,
          sizeForBlockInclusion);
    }

    /**
     * Sign with the algorithm of the DSA type, or with the default one when there is none, and
     * build. When no public key was provided, the part of the signer's key that the algorithm
     * cannot recover is provided, since the signature covers it.
     *
     * @param keys the signer's key pair, of the DSA type's algorithm
     * @return the signed transaction
     */
    public Transaction signAndBuild(final KeyPair keys) {
      checkState(
          signature == null, "The transaction signature has already been provided to this builder");
      if (dsaType.isPresent() && providedPublicKey.isEmpty()) {
        providedPublicKey =
            PublicKeyHandler.providedPart(
                DSAProviderFactory.getAccountEnabledDSA(dsaType.get()), keys.getPublicKey());
      }
      signature(computeSignature(keys));
      sender(
          Address.extract(
              Bytes32.wrap(Hash.hash(Bytes.wrap(keys.getPublicKey().getEncoded())).getBytes())));
      return build();
    }

    Signature computeSignature(final KeyPair keys) {
      final Bytes32 signingHash =
          computeSenderRecoveryHash(
              transactionType,
              dsaType,
              nonce,
              gasPrice,
              maxPriorityFeePerGas,
              maxFeePerGas,
              maxFeePerBlobGas,
              gasLimit,
              to,
              value,
              providedPublicKey,
              payload,
              accessList,
              versionedHashes,
              codeDelegationAuthorizations,
              chainId);
      return dsaType.isPresent()
          ? DSAProviderFactory.getAccountEnabledDSA(dsaType.get())
              .sign(signingHash, keys.getPrivateKey())
          : SignatureAlgorithmFactory.getInstance().sign(signingHash, keys);
    }

    public Builder kzgBlobs(
        final BlobType blobType,
        final List<KZGCommitment> kzgCommitments,
        final List<Blob> blobs,
        final List<KZGProof> kzgProofs) {
      if (this.versionedHashes == null || this.versionedHashes.isEmpty()) {
        this.versionedHashes =
            kzgCommitments.stream()
                .map(c -> new VersionedHash(SHA256_VERSION_ID, Sha256Hash.sha256(c.getData())))
                .toList();
      }
      this.blobsWithCommitments =
          new BlobsWithCommitments(blobType, kzgCommitments, blobs, kzgProofs, versionedHashes);
      return this;
    }

    public Builder blobsWithCommitments(final BlobsWithCommitments blobsWithCommitments) {
      this.blobsWithCommitments = blobsWithCommitments;
      return this;
    }

    public Builder codeDelegations(final List<CodeDelegation> codeDelegations) {
      this.codeDelegationAuthorizations = Optional.ofNullable(codeDelegations);
      return this;
    }
  }
}

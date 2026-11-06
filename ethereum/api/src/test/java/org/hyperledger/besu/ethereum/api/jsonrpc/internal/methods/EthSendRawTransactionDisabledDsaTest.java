/*
 * Copyright contributors to Besu.
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
package org.hyperledger.besu.ethereum.api.jsonrpc.internal.methods;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECP256R1;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequest;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequestContext;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcError;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcErrorResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcSuccessResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.RpcErrorType;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.encoding.EncodingContext;
import org.hyperledger.besu.ethereum.core.encoding.TransactionEncoder;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPool;
import org.hyperledger.besu.ethereum.mainnet.ValidationResult;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * A well-formed transaction signed with an algorithm this node does not enable for accounts is
 * answered with an error that names the algorithm, rather than an internal error, so the sender
 * knows why it was refused.
 */
@ExtendWith(MockitoExtension.class)
class EthSendRawTransactionDisabledDsaTest {

  private static final BigInteger CHAIN_ID = BigInteger.valueOf(1337);

  @Mock private TransactionPool transactionPool;

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
    SignatureAlgorithmFactory.resetInstance();
  }

  @Test
  void aTransactionSignedWithADisabledAlgorithmIsRejectedNamingIt()
      throws InvalidAlgorithmParameterException {
    enableForAccounts(DSAParametersSet.SECP256K1, DSAParametersSet.MLDSA44);
    final String rawTransaction = mlDsaTransaction().toHexString();
    enableForAccounts(DSAParametersSet.SECP256K1);

    final JsonRpcRequestContext request = sendRawTransaction(rawTransaction);
    final JsonRpcResponse response = new EthSendRawTransaction(transactionPool).response(request);

    assertThat(response)
        .usingRecursiveComparison()
        .isEqualTo(
            new JsonRpcErrorResponse(
                request.getRequest().getId(),
                new JsonRpcError(
                    RpcErrorType.INVALID_TRANSACTION_PARAMS.getCode(),
                    "DSA type MLDSA44 (0x"
                        + String.format("%04x", DSAParametersSet.MLDSA44.getId())
                        + ") is not enabled for accounts on this node",
                    null)));
    verifyNoInteractions(transactionPool);
  }

  @Test
  void aTransactionSignedWithAnEnabledAlgorithmStillReachesThePool()
      throws InvalidAlgorithmParameterException {
    enableForAccounts(DSAParametersSet.SECP256K1, DSAParametersSet.MLDSA44);
    when(transactionPool.addTransactionViaApi(any(Transaction.class)))
        .thenReturn(ValidationResult.valid());

    final JsonRpcRequestContext request = sendRawTransaction(mlDsaTransaction().toHexString());
    final JsonRpcResponse response = new EthSendRawTransaction(transactionPool).response(request);

    assertThat(response).isInstanceOf(JsonRpcSuccessResponse.class);
  }

  @Test
  void aStandardTransactionIsRejectedNamingSecp256k1WhenItIsNotEnabled()
      throws InvalidAlgorithmParameterException {
    enableForAccounts(DSAParametersSet.MLDSA44);

    assertRejectedNaming(
        standardTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair()),
        DSAParametersSet.SECP256K1);
  }

  @Test
  void aStandardTransactionIsRejectedNamingSecp256r1WhenItIsNotEnabledOnASecp256r1Network()
      throws InvalidAlgorithmParameterException {
    SignatureAlgorithmFactory.resetInstance();
    SignatureAlgorithmFactory.setInstance(new SECP256R1());
    enableForAccounts(DSAParametersSet.SECP256K1, DSAParametersSet.MLDSA44);

    assertRejectedNaming(
        standardTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair()),
        DSAParametersSet.SECP256R1);
  }

  @Test
  void aStandardTransactionStillReachesThePoolWhenTheCurveIsEnabled()
      throws InvalidAlgorithmParameterException {
    enableForAccounts(DSAParametersSet.SECP256K1);
    when(transactionPool.addTransactionViaApi(any(Transaction.class)))
        .thenReturn(ValidationResult.valid());

    final JsonRpcRequestContext request =
        sendRawTransaction(
            standardTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair())
                .toHexString());
    final JsonRpcResponse response = new EthSendRawTransaction(transactionPool).response(request);

    assertThat(response).isInstanceOf(JsonRpcSuccessResponse.class);
  }

  /** The same error a flexible transaction of a type that is not enabled gets. */
  private void assertRejectedNaming(final Bytes rawTransaction, final DSAParametersSet curve) {
    final JsonRpcRequestContext request = sendRawTransaction(rawTransaction.toHexString());
    final JsonRpcResponse response = new EthSendRawTransaction(transactionPool).response(request);

    assertThat(response)
        .usingRecursiveComparison()
        .isEqualTo(
            new JsonRpcErrorResponse(
                request.getRequest().getId(),
                new JsonRpcError(
                    RpcErrorType.INVALID_TRANSACTION_PARAMS.getCode(),
                    "DSA type "
                        + curve.getName()
                        + " (0x"
                        + String.format("%04x", curve.getId())
                        + ") is not enabled for accounts on this node",
                    null)));
    verifyNoInteractions(transactionPool);
  }

  /** An EIP-1559 transaction signed with the network's curve, in its pooled encoding. */
  private static Bytes standardTransaction(final KeyPair signer) {
    return TransactionEncoder.encodeOpaqueBytes(
        Transaction.builder()
            .type(TransactionType.EIP1559)
            .chainId(CHAIN_ID)
            .nonce(0)
            .maxPriorityFeePerGas(Wei.of(1))
            .maxFeePerGas(Wei.of(10))
            .gasLimit(21_000)
            .to(Address.fromHexString("0x000000000000000000000000000000000000beef"))
            .value(Wei.of(1))
            .payload(Bytes.EMPTY)
            .signAndBuild(signer),
        EncodingContext.POOLED_TRANSACTION);
  }

  private static void enableForAccounts(final DSAParametersSet... enabled)
      throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(enabled));
    config.setNodeActiveDSA(DSAParametersSet.SECP256K1.getName());
    DSAProviderFactory.setDsaProvider(config, null);
  }

  private static JsonRpcRequestContext sendRawTransaction(final String rawTransaction) {
    return new JsonRpcRequestContext(
        new JsonRpcRequest("2.0", "eth_sendRawTransaction", new String[] {rawTransaction}));
  }

  /** A FLEXIBLE_EIP1559 transaction signed with ML-DSA-44, in its pooled encoding. */
  private static Bytes mlDsaTransaction() {
    final DigitalSignatureAlgorithm mlDsa =
        new SupportedAlgorithms().getDSAByName(DSAParametersSet.MLDSA44.getName()).get();
    final KeyPair keyPair = mlDsa.generateNodeKeyPair();
    // The signing hash covers every field but the signature, so a placeholder is enough to read it.
    final Bytes signingHash =
        Bytes.wrap(
            unsigned(keyPair.getPublicKey())
                .signature(mlDsa.sign(Bytes32.ZERO, keyPair.getPrivateKey()))
                .build()
                .getSigningHash());
    final Signature signature = mlDsa.sign(signingHash, keyPair.getPrivateKey());
    return TransactionEncoder.encodeOpaqueBytes(
        unsigned(keyPair.getPublicKey()).signature(signature).build(),
        EncodingContext.POOLED_TRANSACTION);
  }

  private static Transaction.Builder unsigned(final PublicKey publicKey) {
    return Transaction.builder()
        .type(TransactionType.FLEXIBLE_EIP1559)
        .dsaType(DSAParametersSet.MLDSA44.getId())
        .chainId(CHAIN_ID)
        .nonce(0)
        .maxPriorityFeePerGas(Wei.of(1))
        .maxFeePerGas(Wei.of(10))
        .gasLimit(21_000)
        .to(Address.fromHexString("0x000000000000000000000000000000000000beef"))
        .value(Wei.of(1))
        .payload(Bytes.EMPTY)
        .accessList(List.of())
        .providedPublicKey(Optional.of(publicKey));
  }
}

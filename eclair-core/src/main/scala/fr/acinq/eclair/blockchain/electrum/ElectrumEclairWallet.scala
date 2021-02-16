/*
 * Copyright 2019 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.eclair.blockchain.electrum

import akka.actor.{ActorRef, ActorSystem}
import akka.pattern.ask
import fr.acinq.bitcoin.{ByteVector32, Crypto, PublicKey, Satoshi, Script, Transaction, TxOut}
import fr.acinq.eclair.addressToPublicKeyScript
import fr.acinq.eclair.blockchain.electrum.ElectrumClient.BroadcastTransaction
import fr.acinq.eclair.blockchain.electrum.ElectrumWallet._
import fr.acinq.eclair.blockchain.fee.FeeratePerKw
import fr.acinq.eclair.blockchain.{EclairWallet, MakeFundingTxResponse, OnChainBalance}
import grizzled.slf4j.Logging
import scodec.bits.ByteVector
import fr.acinq.eclair.KotlinUtils._

import scala.concurrent.{ExecutionContext, Future}

class ElectrumEclairWallet(val wallet: ActorRef, chainHash: ByteVector32)(implicit system: ActorSystem, ec: ExecutionContext, timeout: akka.util.Timeout) extends EclairWallet with Logging {

  override def getBalance: Future[OnChainBalance] = (wallet ? GetBalance).mapTo[GetBalanceResponse].map(balance => OnChainBalance(balance.confirmed, balance.unconfirmed))

  override def getReceiveAddress: Future[String] = (wallet ? GetCurrentReceiveAddress).mapTo[GetCurrentReceiveAddressResponse].map(_.address)

  override def getReceivePubkey(receiveAddress: Option[String] = None): Future[PublicKey] = Future.failed(new RuntimeException("Not implemented"))

  def getXpub: Future[GetXpubResponse] = (wallet ? GetXpub).mapTo[GetXpubResponse]

  override def makeFundingTx(pubkeyScript: ByteVector, amount: Satoshi, feeRatePerKw: FeeratePerKw): Future[MakeFundingTxResponse] = {
    val tx = new Transaction(2, Nil, new TxOut(amount, pubkeyScript) :: Nil, 0)
    (wallet ? CompleteTransaction(tx, feeRatePerKw)).mapTo[CompleteTransactionResponse].map {
      case CompleteTransactionResponse(tx1, fee1, None) => MakeFundingTxResponse(tx1, 0, fee1)
      case CompleteTransactionResponse(_, _, Some(error)) => throw error
    }
  }

  override def commit(tx: Transaction): Future[Boolean] =
    (wallet ? BroadcastTransaction(tx)) flatMap {
      case ElectrumClient.BroadcastTransactionResponse(tx, None) =>
        //tx broadcast successfully: commit tx
        wallet ? CommitTransaction(tx)
      case ElectrumClient.BroadcastTransactionResponse(tx, Some(error)) if error.message.contains("transaction already in block chain") =>
        // tx was already in the blockchain, that's weird but it is OK
        wallet ? CommitTransaction(tx)
      case ElectrumClient.BroadcastTransactionResponse(_, Some(error)) =>
        //tx broadcast failed: cancel tx
        logger.error(s"cannot broadcast tx ${tx.txid}: $error")
        wallet ? CancelTransaction(tx)
      case ElectrumClient.ServerError(ElectrumClient.BroadcastTransaction(tx), error) =>
        //tx broadcast failed: cancel tx
        logger.error(s"cannot broadcast tx ${tx.txid}: $error")
        wallet ? CancelTransaction(tx)
    } map {
      case CommitTransactionResponse(_) => true
      case CancelTransactionResponse(_) => false
    }

  def sendPayment(amount: Satoshi, address: String, feeRatePerKw: FeeratePerKw): Future[String] = {
    val publicKeyScript = Script.write(addressToPublicKeyScript(address, chainHash))
    val tx = new Transaction(2, Nil, new TxOut(amount, publicKeyScript) :: Nil, 0)
    (wallet ? CompleteTransaction(tx, feeRatePerKw))
      .mapTo[CompleteTransactionResponse]
      .flatMap {
        case CompleteTransactionResponse(tx, _, None) => commit(tx).map {
          case true => tx.txid.toString()
          case false => throw new RuntimeException(s"could not commit tx=$tx")
        }
        case CompleteTransactionResponse(_, _, Some(error)) => throw error
      }
  }

  def sendAll(address: String, feeRatePerKw: FeeratePerKw): Future[(Transaction, Satoshi)] = {
    val publicKeyScript = Script.write(addressToPublicKeyScript(address, chainHash))
    (wallet ? SendAll(ByteVector.view(publicKeyScript), feeRatePerKw))
      .mapTo[SendAllResponse]
      .map {
        case SendAllResponse(tx, fee) => (tx, fee)
      }
  }

  override def rollback(tx: Transaction): Future[Boolean] = (wallet ? CancelTransaction(tx)).map(_ => true)

  override def doubleSpent(tx: Transaction): Future[Boolean] = {
    (wallet ? IsDoubleSpent(tx)).mapTo[IsDoubleSpentResponse].map(_.isDoubleSpent)
  }

}

/*
 * Copyright 2020 ACINQ SAS
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

package fr.acinq.eclair.blockchain.watchdogs

import akka.actor.testkit.typed.scaladsl.{ScalaTestWithActorTestKit, TestProbe}
import akka.actor.typed.eventstream.EventStream
import com.typesafe.config.ConfigFactory
import fr.acinq.bitcoin.Block
import fr.acinq.eclair.blockchain.watchdogs.BlockchainWatchdog.{DangerousBlocksSkew, WrappedCurrentBlockCount}
import fr.acinq.eclair.tor.Socks5ProxyParams
import fr.acinq.eclair.{NodeParams, TestConstants, TestTags}
import org.scalatest.funsuite.AnyFunSuiteLike

import java.net.{InetSocketAddress, Socket}
import scala.concurrent.duration.DurationInt
import scala.util.Try

class BlockchainWatchdogSpec extends ScalaTestWithActorTestKit(ConfigFactory.load("application")) with AnyFunSuiteLike {

  // blockcypher.com is very flaky - it either imposes rate limits or requires captcha
  // but sometimes it works. If want to check whether you're lucky uncomment these lines:
  //  val nodeParamsLivenet = TestConstants.Alice.nodeParams.copy(chainHash = Block.LivenetGenesisBlock.hash)
  //  val nodeParamsTestnet = TestConstants.Alice.nodeParams.copy(chainHash = Block.TestnetGenesisBlock.hash)
  // and comment these:
  val nodeParamsLivenet = removeBlockcypher(TestConstants.Alice.nodeParams.copy(chainHash = Block.LivenetGenesisBlock.hash))
  val nodeParamsTestnet = removeBlockcypher(TestConstants.Alice.nodeParams.copy(chainHash = Block.TestnetGenesisBlock.hash))


  test("fetch block headers from four sources on mainnet", TestTags.ExternalApi) {
    val eventListener = TestProbe[DangerousBlocksSkew]()
    system.eventStream ! EventStream.Subscribe(eventListener.ref)
    val watchdog = testKit.spawn(BlockchainWatchdog(nodeParamsLivenet, 1 second))
    watchdog ! WrappedCurrentBlockCount(630561)

    val events = Seq(
      eventListener.expectMessageType[DangerousBlocksSkew],
      eventListener.expectMessageType[DangerousBlocksSkew],
      eventListener.expectMessageType[DangerousBlocksSkew],
      //      eventListener.expectMessageType[DangerousBlocksSkew]
    )
    eventListener.expectNoMessage(100 millis)
    //    assert(events.map(_.recentHeaders.source).toSet === Set("bitcoinheaders.net", "blockcypher.com", "blockstream.info", "mempool.space"))
    assert(events.map(_.recentHeaders.source).toSet === Set("bitcoinheaders.net", "blockstream.info", "mempool.space"))
    testKit.stop(watchdog)
  }

  test("fetch block headers from three sources on testnet", TestTags.ExternalApi) {
    val eventListener = TestProbe[DangerousBlocksSkew]()
    system.eventStream ! EventStream.Subscribe(eventListener.ref)
    val watchdog = testKit.spawn(BlockchainWatchdog(nodeParamsTestnet, 1 second))
    watchdog ! WrappedCurrentBlockCount(500000)

    val events = Seq(
      eventListener.expectMessageType[DangerousBlocksSkew],
      eventListener.expectMessageType[DangerousBlocksSkew],
      //      eventListener.expectMessageType[DangerousBlocksSkew]
    )
    eventListener.expectNoMessage(100 millis)
    //    assert(events.map(_.recentHeaders.source).toSet === Set("blockcypher.com", "blockstream.info", "mempool.space"))
    assert(events.map(_.recentHeaders.source).toSet === Set("blockstream.info", "mempool.space"))
    testKit.stop(watchdog)
  }

  test("fetch block headers when we don't receive blocks", TestTags.ExternalApi) {
    val eventListener = TestProbe[DangerousBlocksSkew]()
    system.eventStream ! EventStream.Subscribe(eventListener.ref)
    val blockTimeout = 5 seconds
    val watchdog = testKit.spawn(BlockchainWatchdog(nodeParamsTestnet, 1 second, blockTimeout))

    watchdog ! WrappedCurrentBlockCount(500000)
    assert(eventListener.expectMessageType[DangerousBlocksSkew].recentHeaders.currentBlockCount === 500000)
    assert(eventListener.expectMessageType[DangerousBlocksSkew].recentHeaders.currentBlockCount === 500000)
//    assert(eventListener.expectMessageType[DangerousBlocksSkew].recentHeaders.currentBlockCount === 500000)
    eventListener.expectNoMessage(100 millis)

    // If we don't receive blocks, we check blockchain sources.
    assert(eventListener.expectMessageType[DangerousBlocksSkew].recentHeaders.currentBlockCount === 500000)
    assert(eventListener.expectMessageType[DangerousBlocksSkew].recentHeaders.currentBlockCount === 500000)
//    assert(eventListener.expectMessageType[DangerousBlocksSkew].recentHeaders.currentBlockCount === 500000)
    eventListener.expectNoMessage(100 millis)

    // And we keep checking blockchain sources until we receive a block.
    assert(eventListener.expectMessageType[DangerousBlocksSkew].recentHeaders.currentBlockCount === 500000)
    assert(eventListener.expectMessageType[DangerousBlocksSkew].recentHeaders.currentBlockCount === 500000)
//    assert(eventListener.expectMessageType[DangerousBlocksSkew].recentHeaders.currentBlockCount === 500000)
    eventListener.expectNoMessage(100 millis)
  }

  test("fetch block headers on mainnet over Tor", TestTags.ExternalApi) {
    val proxyParams = Socks5ProxyParams(new InetSocketAddress("127.0.0.1", 9050),
      credentials_opt = None,
      randomizeCredentials = true,
      useForIPv4 = true,
      useForIPv6 = true,
      useForTor = true)

    if (proxyAcceptsConnections(proxyParams)) {
      val eventListener = TestProbe[DangerousBlocksSkew]()
      system.eventStream ! EventStream.Subscribe(eventListener.ref)

      val nodeParams = nodeParamsLivenet.copy(socksProxy_opt = Some(proxyParams))
      val watchdog = testKit.spawn(BlockchainWatchdog(nodeParams, 1 second))
      watchdog ! WrappedCurrentBlockCount(630561)

      val events = Seq(
        eventListener.expectMessageType[DangerousBlocksSkew],
        eventListener.expectMessageType[DangerousBlocksSkew],
//        eventListener.expectMessageType[DangerousBlocksSkew]
      )
      eventListener.expectNoMessage(100 millis)
      assert(events.map(_.recentHeaders.source).toSet === Set("blockstream.info", "mempool.space"))
      testKit.stop(watchdog)
    } else {
      cancel("Tor daemon is not up and running")
    }
  }

  private def proxyAcceptsConnections(proxyParams: Socks5ProxyParams): Boolean = Try {
    val s = new Socket(proxyParams.address.getAddress, proxyParams.address.getPort)
    s.close()
  }.isSuccess

  private def removeBlockcypher(nodeParams: NodeParams): NodeParams = {
    nodeParams.copy(blockchainWatchdogSources = nodeParams.blockchainWatchdogSources.filterNot(_ == "blockcypher.com"))
  }
}

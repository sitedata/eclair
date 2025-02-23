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

package fr.acinq.eclair.gui

import java.io.File

import akka.actor.{ActorSystem, Props, SupervisorStrategy}
import fr.acinq.eclair._
import fr.acinq.eclair.blockchain.bitcoind.zmq.ZMQActor._
import fr.acinq.eclair.channel.ChannelEvent
import fr.acinq.eclair.gui.controllers.{MainController, NotificationsController}
import fr.acinq.eclair.payment.PaymentEvent
import fr.acinq.eclair.router.NetworkEvent
import grizzled.slf4j.Logging
import javafx.application.Preloader.ErrorNotification
import javafx.application.{Application, Platform}
import javafx.event.EventHandler
import javafx.fxml.FXMLLoader
import javafx.scene.image.Image
import javafx.scene.{Parent, Scene}
import javafx.stage.{Popup, Screen, Stage, WindowEvent}

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Promise
import scala.util.{Failure, Success, Try}


/**
 * Created by PM on 16/08/2016.
 */
class FxApp extends Application with Logging {

  override def init = {
    logger.debug("initializing application...")
  }

  def onError(t: Throwable): Unit = t match {
    case e@TCPBindException(port) =>
      notifyPreloader(new ErrorNotification("Setup", s"Could not bind to port $port", e))
    case e: BitcoinRPCConnectionException =>
      notifyPreloader(new ErrorNotification("Setup", "Could not connect to Bitcoin Core using JSON-RPC.", e))
      notifyPreloader(new AppNotification(InfoAppNotification, "Make sure that Bitcoin Core is up and running and RPC parameters are correct."))
    case e@BitcoinZMQConnectionTimeoutException =>
      notifyPreloader(new ErrorNotification("Setup", "Could not connect to Bitcoin Core using ZMQ.", e))
      notifyPreloader(new AppNotification(InfoAppNotification, "Make sure that Bitcoin Core is up and running and ZMQ parameters are correct."))
    case e@IncompatibleDBException =>
      notifyPreloader(new ErrorNotification("Setup", "Breaking changes!", e))
      notifyPreloader(new AppNotification(InfoAppNotification, "Eclair is still in alpha, and under heavy development. Last update was not backward compatible."))
      notifyPreloader(new AppNotification(InfoAppNotification, "Please reset your datadir."))
    case e@IncompatibleNetworkDBException =>
      notifyPreloader(new ErrorNotification("Setup", "Unreadable network database!", e))
      notifyPreloader(new AppNotification(InfoAppNotification, "Could not read the network database. Please remove the file and restart."))
    case t: Throwable =>
      notifyPreloader(new ErrorNotification("Setup", s"Error: ${t.getLocalizedMessage}", t))
  }

  override def start(primaryStage: Stage): Unit = {
    new Thread(new Runnable {
      override def run(): Unit = {
        try {
          val icon = new Image(getClass.getResource("/gui/commons/images/eclair-square.png").toExternalForm, false)
          primaryStage.getIcons.add(icon)
          val mainFXML = new FXMLLoader(getClass.getResource("/gui/main/main.fxml"))
          val pKit = Promise[Kit]()
          val handlers = new Handlers(pKit.future)
          val controller = new MainController(handlers, getHostServices)
          mainFXML.setController(controller)
          val mainRoot = mainFXML.load[Parent]
          val datadir = new File(getParameters.getUnnamed.get(0))
          val config = NodeParams.loadConfiguration(datadir)
          implicit val system = ActorSystem("eclair-node-gui", config)
          val setup = new Setup(datadir, pluginParams = Seq.empty)

          val unitConf = setup.config.getString("gui.unit")
          FxApp.unit = Try(CoinUtils.getUnitFromString(unitConf)) match {
            case Failure(_) =>
              logger.warn(s"$unitConf is not a valid gui unit, must be msat, sat, bits, mbtc or btc. Defaulting to btc.")
              BtcUnit
            case Success(u) => u
          }
          CoinUtils.setCoinPattern(CoinUtils.getPatternFromUnit(FxApp.unit))

          val guiUpdater = system.actorOf(SimpleSupervisor.props(Props(classOf[GUIUpdater], controller), "gui-updater", SupervisorStrategy.Resume))
          system.eventStream.subscribe(guiUpdater, classOf[ChannelEvent])
          system.eventStream.subscribe(guiUpdater, classOf[NetworkEvent])
          system.eventStream.subscribe(guiUpdater, classOf[PaymentEvent])
          system.eventStream.subscribe(guiUpdater, classOf[ZMQEvent])
          pKit.completeWith(setup.bootstrap)
          pKit.future.onComplete {
            case Success(kit) =>
              Boot.startApiServiceIfEnabled(kit)
              Platform.runLater(new Runnable {
                override def run(): Unit = {
                  val scene = new Scene(mainRoot)
                  primaryStage.setTitle("Eclair")
                  primaryStage.setMinWidth(750)
                  primaryStage.setWidth(980)
                  primaryStage.setMinHeight(400)
                  primaryStage.setHeight(640)
                  primaryStage.setOnCloseRequest(new EventHandler[WindowEvent] {
                    override def handle(event: WindowEvent): Unit = {
                      logger.info(s"Close Requested")
                      System.exit(0)
                    }
                  })
                  controller.initInfoFields(setup)
                  primaryStage.setScene(scene)
                  primaryStage.show
                  notifyPreloader(new AppNotification(SuccessAppNotification, "Init successful"))
                  initNotificationStage(primaryStage, handlers)
                }
              })
            case Failure(t) => onError(t)
          }
        } catch {
          case t: Throwable => onError(t)
        }
      }
    }).start

  }

  /**
   * Initialize the notification stage and assign it to the handler class.
   *
   * @param owner         stage owning the notification stage
   * @param notifhandlers Handles the notifications
   */
  private def initNotificationStage(owner: Stage, notifhandlers: Handlers) = {
    // get fxml/controller
    val notifFXML = new FXMLLoader(getClass.getResource("/gui/main/notifications.fxml"))
    val notifsController = new NotificationsController
    notifFXML.setController(notifsController)
    val root = notifFXML.load[Parent]

    Platform.runLater(new Runnable() {
      override def run = {
        // create scene
        val popup = new Popup
        popup.setHideOnEscape(false)
        popup.setAutoFix(false)
        val margin = 10
        val width = 400
        popup.setWidth(margin + width)
        popup.getContent.add(root)
        // positioning the popup @ TOP RIGHT of screen
        val screenBounds = Screen.getPrimary.getVisualBounds
        popup.show(owner, screenBounds.getMaxX - (margin + width), screenBounds.getMinY + margin)
        notifhandlers.initNotifications(notifsController)
      }
    })
  }
}

object FxApp {
  private var unit: CoinUnit = BtcUnit
  def getUnit = FxApp.unit
}
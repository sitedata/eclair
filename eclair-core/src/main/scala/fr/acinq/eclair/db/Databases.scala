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

package fr.acinq.eclair.db

import akka.Done
import akka.actor.{ActorSystem, CoordinatedShutdown}
import com.typesafe.config.Config
import com.zaxxer.hikari.{HikariConfig, HikariDataSource}
import fr.acinq.eclair.db.pg.PgUtils.PgLock.LockFailureHandler
import fr.acinq.eclair.db.pg.PgUtils._
import fr.acinq.eclair.db.pg._
import fr.acinq.eclair.db.sqlite._
import grizzled.slf4j.Logging

import java.io.File
import java.nio.file._
import java.sql.Connection
import java.util.UUID
import scala.concurrent.Future
import scala.concurrent.duration._

trait Databases {
  //@formatter:off
  def network: NetworkDb
  def audit: AuditDb
  def channels: ChannelsDb
  def peers: PeersDb
  def payments: PaymentsDb
  def pendingCommands: PendingCommandsDb
  //@formatter:on
}

object Databases extends Logging {

  trait FileBackup {
    this: Databases =>
    def backup(backupFile: File): Unit
  }

  trait ExclusiveLock {
    this: Databases =>
    def obtainExclusiveLock(): Unit
  }

  case class SqliteDatabases private(network: SqliteNetworkDb,
                                     audit: SqliteAuditDb,
                                     channels: SqliteChannelsDb,
                                     peers: SqlitePeersDb,
                                     payments: SqlitePaymentsDb,
                                     pendingCommands: SqlitePendingCommandsDb,
                                     private val backupConnection: Connection) extends Databases with FileBackup {
    override def backup(backupFile: File): Unit = SqliteUtils.using(backupConnection.createStatement()) {
      statement => {
        statement.executeUpdate(s"backup to ${backupFile.getAbsolutePath}")
      }
    }
  }

  object SqliteDatabases {
    def apply(auditJdbc: Connection, networkJdbc: Connection, eclairJdbc: Connection): SqliteDatabases = SqliteDatabases(
      network = new SqliteNetworkDb(networkJdbc),
      audit = new SqliteAuditDb(auditJdbc),
      channels = new SqliteChannelsDb(eclairJdbc),
      peers = new SqlitePeersDb(eclairJdbc),
      payments = new SqlitePaymentsDb(eclairJdbc),
      pendingCommands = new SqlitePendingCommandsDb(eclairJdbc),
      backupConnection = eclairJdbc
    )
  }

  case class PostgresDatabases private(network: PgNetworkDb,
                                       audit: PgAuditDb,
                                       channels: PgChannelsDb,
                                       peers: PgPeersDb,
                                       payments: PgPaymentsDb,
                                       pendingCommands: PgPendingCommandsDb,
                                       dataSource: HikariDataSource,
                                       lock: PgLock) extends Databases with ExclusiveLock {
    override def obtainExclusiveLock(): Unit = lock.obtainExclusiveLock(dataSource)
  }

  object PostgresDatabases {
    def apply(hikariConfig: HikariConfig,
              instanceId: UUID,
              lock: PgLock = PgLock.NoLock,
              jdbcUrlFile_opt: Option[File],
              readOnlyUser_opt: Option[String],
              resetJsonColumns: Boolean)(implicit system: ActorSystem): PostgresDatabases = {

      jdbcUrlFile_opt.foreach(jdbcUrlFile => checkIfDatabaseUrlIsUnchanged(hikariConfig.getJdbcUrl, jdbcUrlFile))

      implicit val ds: HikariDataSource = new HikariDataSource(hikariConfig)
      implicit val implicitLock: PgLock = lock

      lock match {
        case PgLock.NoLock => ()
        case l: PgLock.LeaseLock =>
          // we obtain a lock right now...
          l.obtainExclusiveLock(ds)
          // ...and renew the lease regularly
          import system.dispatcher
          val leaseLockTask = system.scheduler.scheduleWithFixedDelay(l.leaseRenewInterval, l.leaseRenewInterval)(() => l.obtainExclusiveLock(ds))

          CoordinatedShutdown(system).addTask(CoordinatedShutdown.PhaseActorSystemTerminate, "release-postgres-lock") { () =>
            Future {
              logger.info("cancelling the pg lock renew task...")
              leaseLockTask.cancel()
              logger.info("releasing the curent pg lock...")
              l.releaseExclusiveLock(ds)
              logger.info("closing the connection pool...")
              ds.close()
              Done
            }
          }
      }

      val databases = PostgresDatabases(
        network = new PgNetworkDb,
        audit = new PgAuditDb,
        channels = new PgChannelsDb,
        peers = new PgPeersDb,
        payments = new PgPaymentsDb,
        pendingCommands = new PgPendingCommandsDb,
        dataSource = ds,
        lock = lock)

      readOnlyUser_opt.foreach { readOnlyUser =>
        PgUtils.inTransaction { connection =>
          using(connection.createStatement()) { statement =>
            val schemas = "public" :: "audit" :: "local" :: "network" :: "payments" :: Nil
            schemas.foreach { schema =>
              logger.info(s"granting read-only access to user=$readOnlyUser schema=$schema")
              statement.executeUpdate(s"GRANT USAGE ON SCHEMA $schema TO $readOnlyUser")
              statement.executeUpdate(s"GRANT SELECT ON ALL TABLES IN SCHEMA $schema TO $readOnlyUser")
            }
          }
        }
      }

      if (resetJsonColumns) {
        logger.warn("resetting json columns...")
        PgUtils.inTransaction { connection =>
          databases.channels.resetJsonColumns(connection)
          databases.network.resetJsonColumns(connection)
        }
      }

      databases
    }

    private def checkIfDatabaseUrlIsUnchanged(url: String, urlFile: File): Unit = {
      def readString(path: Path): String = Files.readAllLines(path).get(0)

      def writeString(path: Path, string: String): Unit = Files.write(path, java.util.Arrays.asList(string))

      if (urlFile.exists()) {
        val oldUrl = readString(urlFile.toPath)
        if (oldUrl != url)
          throw JdbcUrlChanged(oldUrl, url)
      } else {
        writeString(urlFile.toPath, url)
      }
    }
  }

  def init(dbConfig: Config, instanceId: UUID, chaindir: File, db: Option[Databases] = None)(implicit system: ActorSystem): Databases = {
    db match {
      case Some(d) => d
      case None =>
        dbConfig.getString("driver") match {
          case "sqlite" => Databases.sqlite(chaindir)
          case "postgres" => Databases.postgres(dbConfig, instanceId, chaindir)
          case "dual" =>
            val sqlite = Databases.sqlite(chaindir)
            val postgres = Databases.postgres(dbConfig, instanceId, chaindir)
            DualDatabases(sqlite, postgres)
          case driver => throw new RuntimeException(s"unknown database driver `$driver`")
        }
    }
  }

  /**
   * Given a parent folder it creates or loads all the databases from a JDBC connection
   */
  def sqlite(dbdir: File): SqliteDatabases = {
    dbdir.mkdirs()
    SqliteDatabases(
      eclairJdbc = SqliteUtils.openSqliteFile(dbdir, "eclair.sqlite", exclusiveLock = true, journalMode = "wal", syncFlag = "full"), // there should only be one process writing to this file
      networkJdbc = SqliteUtils.openSqliteFile(dbdir, "network.sqlite", exclusiveLock = false, journalMode = "wal", syncFlag = "normal"), // we don't need strong durability guarantees on the network db
      auditJdbc = SqliteUtils.openSqliteFile(dbdir, "audit.sqlite", exclusiveLock = false, journalMode = "wal", syncFlag = "full")
    )
  }

  def postgres(dbConfig: Config, instanceId: UUID, dbdir: File, lockExceptionHandler: LockFailureHandler = LockFailureHandler.logAndStop)(implicit system: ActorSystem): PostgresDatabases = {
    dbdir.mkdirs()
    val database = dbConfig.getString("postgres.database")
    val host = dbConfig.getString("postgres.host")
    val port = dbConfig.getInt("postgres.port")
    val username = if (dbConfig.getIsNull("postgres.username") || dbConfig.getString("postgres.username").isEmpty) None else Some(dbConfig.getString("postgres.username"))
    val password = if (dbConfig.getIsNull("postgres.password") || dbConfig.getString("postgres.password").isEmpty) None else Some(dbConfig.getString("postgres.password"))
    val readOnlyUser_opt = if (dbConfig.getIsNull("postgres.readonly-user") || dbConfig.getString("postgres.readonly-user").isEmpty) None else Some(dbConfig.getString("postgres.readonly-user"))
    val resetJsonColumns = dbConfig.getBoolean("postgres.reset-json-columns")

    val hikariConfig = new HikariConfig()
    hikariConfig.setJdbcUrl(s"jdbc:postgresql://$host:$port/$database")
    username.foreach(hikariConfig.setUsername)
    password.foreach(hikariConfig.setPassword)
    val poolConfig = dbConfig.getConfig("postgres.pool")
    hikariConfig.setMaximumPoolSize(poolConfig.getInt("max-size"))
    hikariConfig.setConnectionTimeout(poolConfig.getDuration("connection-timeout").toMillis)
    hikariConfig.setIdleTimeout(poolConfig.getDuration("idle-timeout").toMillis)
    hikariConfig.setMaxLifetime(poolConfig.getDuration("max-life-time").toMillis)

    val lock = dbConfig.getString("postgres.lock-type") match {
      case "none" => PgLock.NoLock
      case "lease" =>
        val leaseInterval = dbConfig.getDuration("postgres.lease.interval").toSeconds.seconds
        val leaseRenewInterval = dbConfig.getDuration("postgres.lease.renew-interval").toSeconds.seconds
        require(leaseInterval > leaseRenewInterval, "invalid configuration: `db.postgres.lease.interval` must be greater than `db.postgres.lease.renew-interval`")
        // We use a timeout for locks, because we might not be able to get the lock right away due to concurrent access
        // by other threads. That timeout gives time for other transactions to complete, then ours can take the lock
        val lockTimeout = dbConfig.getDuration("postgres.lease.lock-timeout").toSeconds.seconds
        hikariConfig.setConnectionInitSql(s"SET lock_timeout TO '${lockTimeout.toSeconds}s'")
        PgLock.LeaseLock(instanceId, leaseInterval, leaseRenewInterval, lockExceptionHandler)
      case unknownLock => throw new RuntimeException(s"unknown postgres lock type: `$unknownLock`")
    }

    val jdbcUrlFile = new File(dbdir, "last_jdbcurl")

    Databases.PostgresDatabases(
      hikariConfig = hikariConfig,
      instanceId = instanceId,
      lock = lock,
      jdbcUrlFile_opt = Some(jdbcUrlFile),
      readOnlyUser_opt = readOnlyUser_opt,
      resetJsonColumns = resetJsonColumns
    )
  }

}

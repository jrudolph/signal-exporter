package net.virtualvoid.signal

import java.io.File
import java.io.FileOutputStream
import java.util.Date

import net.virtualvoid.signal.BackupFrameEvent.SqlParameter
import net.virtualvoid.signal.BackupReader.BackupRecord
import net.virtualvoid.signal.BackupReader.DataModel
import net.virtualvoid.signal.FrameEventReader.FrameEventConsumer
import net.virtualvoid.signal.RawFrameReader.RawBackupEventConsumer

import scala.collection.mutable.ListBuffer
import scala.io.Source

object Operations {
  def dumpDataAndAttachments(attachmentsDir: File): RawBackupEventConsumer[Unit] =
    RawBackupEventConsumer((), { (_, event) =>
      event match {
        case RawBackupEvent.FrameEvent(frame) => //println(frame)
        case RawBackupEvent.FrameEventWithAttachment(frame, attachmentData) =>
          val fileName =
            if (frame.hasAttachment) s"att-${frame.getAttachment.getAttachmentId}"
            else if (frame.hasAvatar) s"avatar-${frame.getAvatar.getName}"
            else "unknown"

          //println(frame)
          val out = new FileOutputStream(new File(attachmentsDir, s"$fileName.jpg"))
          out.write(attachmentData)
          out.close()
      }
    })

  val PrintEvents = FrameEventConsumer[Unit]((), (_, event) => println(event))

  type Histogram[T] = Map[T, Int]
  object Histogram {
    def Empty[T] = Map.empty[T, Int]
  }
  val PrintFrameTypeHisto =
    FrameEventConsumer.withFinalStep(
      Histogram.Empty[String],
      { (counts: Histogram[String], event: BackupFrameEvent) =>
        val tag = event.productPrefix
        val curCount = counts.getOrElse(tag, 0)
        counts.updated(tag, curCount + 1)
      }) { histo =>
        histo.toSeq.sortBy(-_._2).foreach {
          case (tag, count) =>
            println(f"$count%5d $tag%s")
        }
      }

  val RetrieveRecords = FrameEventConsumer.withFinalStep(
    BackupReader.State(Map.empty, ListBuffer.empty[BackupRecord]),
    {
      BackupReader.recordReader[ListBuffer[BackupRecord]] { (buffer, record) =>
        buffer += record
      }
    })(
      _.t.result
    )

  val PrintRecordHeuristics =
    RetrieveRecords.map { records =>
      val tables = records.toVector.groupBy(_.tableMetadata.tableName)

      tables.foreach {
        case (table, records) =>
          val fields = records.head.tableMetadata.fields.map(_.fieldName)

          println(s"Table [$table]")

          fields.foreach { field =>
            println(s"Field [$table->$field]")

            val grouper: SqlParameter => Any =
              field match {
                case "type" | "msg_box" => // these are bitmaps, structured in a certain way
                  value =>
                    val v = value.asLong
                    (v & 0x1f, v >> 5)
                case _ => identity
              }

            records
              .map(_.data(field))
              .groupBy(grouper)
              .toSeq
              .sortBy(-_._2.size)
              .take(20) foreach { case (value, els) => println(f"${els.size}%5d -> $value%s") }
          }
      }
    }

  val BuildModel = RetrieveRecords.map(DataModel.convertRecordsToModel)

  val ExportToJson =
    BuildModel.map { model =>
      import DataModel.DataModelFormat._
      import spray.json._

      val output = new FileOutputStream("data.json")
      output.write(model.toJson.prettyPrint.getBytes("utf8"))
      output.close()
    }

  val ExportToHtml =
    BuildModel.map { model =>
      import DataModel._
      model.conversations.filter(_.messages.nonEmpty).foreach { c =>
        val name = c.recipients match {
          case g: Group     => g.name
          case r: Recipient => r.name
        }
        val nameClean = name.filter(_.isLetter)
        val fos = new FileOutputStream(s"conversations/$nameClean.html")
        fos.write(
          """
            |<html>
            |<body>
            |<table>
            |""".stripMargin.getBytes("utf8"))

        def dateString(date: Long): String = new Date(date).toString
        def whoString(m: SimpleMessage): String =
          if (m.`type` == Sent) "me"
          else c.recipients match {
            case g: Group     => g.recipients.find(_.phone == m.from.get).fold("unknown")(_.name)
            case r: Recipient => r.name
          }

        c.messages.foreach { m =>
          val maybePicture =
            m match {
              case MediaMessage(message, attachment) =>
                val ref = s"../attachments/att-${attachment.uniqueId}.jpg"
                s"""<td><a href="$ref"><img width="100" src="$ref" alt="${attachment.fileName}"/></a></td>"""
              case _ => "<td/>"
            }
          fos.write(
            s"""<tr><td>${dateString(m.message.dateSentMillis)}</td><td>${whoString(m.message)}</td>$maybePicture<td>${m.message.body}</td></tr>"""
              .stripMargin.getBytes("utf8")
          )
        }

        fos.write("""
                    |</table>
                    |</body>
                    |</html>
                  """.stripMargin.getBytes("utf8"))
        fos.close()
      }
    }
}

object Exporter {
  def existingFile(role: String, path: String): File = {
    val file = new File(path)
    if (!file.exists) {
      println(s"$role is missing at ${file.getAbsolutePath}")
      sys.exit(1)
    }
    file
  }

  val backupFile = existingFile("Backup file", "backup.bin")
  val passFile = existingFile("Passphrase file", "passphrase.txt")
  val pass = Source.fromFile(passFile).mkString
  require(pass.length == 30, s"Passphrase must have 30 characters but had ${pass.length}")

  val attachmentsDir = existingFile("Attachments dir", "attachments")

  def main(args: Array[String]): Unit =
    try {
      //dumpAttachments()
      //exportToHtml()
      //exportToJson()
      //printEvents()
    } catch {
      case x: Throwable => x.printStackTrace()
    }
}

object BackupReader {

  final case class FieldMetadata(
      fieldName: String,
      tpe:       String,
      extra:     String
  )
  final case class TableMetadata(
      tableName: String,
      fields:    Seq[FieldMetadata])
  final case class BackupRecord(
      tableMetadata: TableMetadata,
      data:          Map[String, BackupFrameEvent.SqlParameter]
  )
  final case class State[T](tableMetadata: Map[String, TableMetadata], t: T)
  val CreateTable = """CREATE TABLE (\w+) \(([^)]*)\)""".r
  val FieldSpec = """\s*(\w+) (\w+)(?: (.*))?""".r
  val Insert = """INSERT INTO (\w+) VALUES \([?,]*\)""".r
  def recordReader[T](f: (T, BackupRecord) => T)(state: State[T], event: BackupFrameEvent): State[T] = event match {
    case BackupFrameEvent.SqlStatement(statement, parameters) =>
      statement match {
        case CreateTable(tableName, fieldSpecs) =>
          val fields =
            fieldSpecs.split(",").map {
              case FieldSpec(name, tpe, extra) =>
                FieldMetadata(name, tpe, if (extra ne null) extra else "")
            }

          val tableMeta = TableMetadata(tableName, fields)
          if (parameters.nonEmpty) println(s"WARN: CREATE TABLE statement [$statement] had non-empty parameters: [$parameters]")
          state.copy(tableMetadata = state.tableMetadata + (tableName -> tableMeta))
        case Insert(tableName) =>
          state.tableMetadata.get(tableName) match {
            case None =>
              println(s"WARN: got insert for unknown table [$tableName], ignoring, [$event]")
              state
            case Some(metadata) =>
              if (metadata.fields.size != parameters.size) {
                println(s"WARN: got unexpected number of parameters for insert statement got [${parameters.size}] expected [${metadata.fields.size}] for table [$tableName] [$event]")
                state
              } else {
                val fieldMap = (metadata.fields.map(_.fieldName), parameters).zipped.toMap
                val record = BackupRecord(metadata, fieldMap)
                state.copy(t = f(state.t, record))
              }
          }
        case _ => state
      }
    case _ => state
  }

  object DataModel {

    sealed trait Recipients
    final case class Recipient(
        phone: String,
        name:  String) extends Recipients
    final case class Group(
        name:       String,
        recipients: Seq[Recipient]
    ) extends Recipients

    sealed trait MessageType
    case object Received extends MessageType
    case object Sent extends MessageType
    case class Other(value: Int) extends MessageType

    sealed trait Message {
      def message: SimpleMessage
    }
    final case class SimpleMessage(
        body:           String,
        `type`:         MessageType,
        from:           Option[String],
        dateSentMillis: Long
    ) extends Message {
      override def message: SimpleMessage = this
    }
    final case class Attachment(
        uniqueId:    Long,
        fileName:    String,
        contentType: String
    )
    final case class MediaMessage(
        message:    SimpleMessage,
        attachment: Attachment
    ) extends Message

    final case class Conversation(
        recipients: Recipients,
        messages:   Seq[Message]
    )
    final case class SignalData(
        conversations: Seq[Conversation]
    )

    object DataModelFormat {
      import spray.json._
      import DefaultJsonProtocol._

      implicit def otherTypeFormat: JsonFormat[Other] = jsonFormat1(Other)
      implicit def messageTypeFormat: JsonFormat[MessageType] =
        new JsonFormat[MessageType] {
          override def read(json: JsValue): MessageType = ???
          override def write(obj: MessageType): JsValue = obj match {
            case Received => JsString("received")
            case Sent     => JsString("sent")
            case o: Other => o.toJson
          }
        }
      implicit def recipientFormat: JsonFormat[Recipient] = jsonFormat2(Recipient)
      implicit def groupFormat: JsonFormat[Group] = jsonFormat2(Group)
      implicit def recipientsFormat: JsonFormat[Recipients] =
        new JsonFormat[Recipients] {
          override def read(json: JsValue): Recipients = ???
          override def write(obj: Recipients): JsValue = obj match {
            case r: Recipient => r.toJson
            case g: Group     => g.toJson
          }
        }

      implicit def simpleMessageFormat: JsonFormat[SimpleMessage] = jsonFormat4(SimpleMessage)
      implicit def attachmentFormat: JsonFormat[Attachment] = jsonFormat3(Attachment)
      implicit def mediaMessageFormat: JsonFormat[MediaMessage] = jsonFormat2(MediaMessage)
      implicit def messageFormat: JsonFormat[Message] =
        new JsonFormat[Message] {
          override def read(json: JsValue): Message = ???
          override def write(obj: Message): JsValue = obj match {
            case m: SimpleMessage => m.toJson
            case m: MediaMessage  => m.toJson
          }
        }
      implicit def conversationFormat: JsonFormat[Conversation] = jsonFormat2(Conversation)
      implicit def signalDataFormat: JsonFormat[SignalData] = jsonFormat1(SignalData)
    }

    object Constants {
      // https://github.com/signalapp/Signal-Android/blob/f6951b9ae0e38357ba8c5be2a13c666e176519d8/src/org/thoughtcrime/securesms/database/MmsSmsColumns.java#L27

      val BaseInfoMask = 0x1f

      val Received = 20
      val Sent = 23
    }

    def combineMaps[K, V](map1: Map[K, V], map2: Map[K, V], zeroV: V)(f: (V, V) => V): Map[K, V] = {
      val allKeys = map1.keys ++ map2.keys
      allKeys.map { key =>
        key -> f(map1.getOrElse(key, zeroV), map2.getOrElse(key, zeroV))
      }.toMap
    }
    def convertRecordsToModel(records: Seq[BackupRecord]): SignalData = {
      val tables = records.groupBy(_.tableMetadata.tableName)
      val prefs = tables("recipient_preferences")
      val groups = tables("groups")
      val parts = tables("part")

      def singleRecipientInfo(phone: String): Recipient = {
        val name =
          prefs.find(_.data("recipient_ids").asString == phone).fold("<unknown>")(_.data("system_display_name").asString)
        Recipient(phone, name)
      }
      def groupInfo(groupId: String): Group =
        groups.find(_.data("group_id").asString == groupId) match {
          case Some(groupRow) =>
            val members = groupRow.data("members").asString.split(',').map(singleRecipientInfo)
            Group(groupRow.data("title").asString, members)
          case None =>
            println(s"WARN: didn't find group details for [$groupId]")
            Group(groupId, Nil)
        }

      def threadInfo(threadId: Long): Recipients = {
        val threadRow = tables("thread").find(_.data("_id").asLong == threadId).get
        val recps = threadRow.data("recipient_ids").asString

        if (recps.contains("__textsecure_group"))
          groupInfo(recps)
        else
          singleRecipientInfo(recps)
      }
      def typeByFlags(flags: Long): Option[MessageType] =
        flags & Constants.BaseInfoMask match {
          case Constants.Received => Some(Received)
          case Constants.Sent     => Some(Sent)
          case other              => None // Other(other.toInt)
        }
      def conversations: Seq[Conversation] = {
        val smsByThread = tables("sms").groupBy(_.data("thread_id").asLong)

        val smsConvs: Map[Long, Seq[Message]] =
          smsByThread.mapValues { records =>
            records.sortBy(_.data("date_sent").asLong).flatMap { row =>
              typeByFlags(row.data("type").asLong).map { tpe =>
                SimpleMessage(
                  row.data("body").asString,
                  tpe,
                  if (tpe == Received) Some(row.data("address").asString) else None,
                  row.data("date_sent").asLong
                )
              }
            }
          }

        val mmsByThread = tables("mms").groupBy(_.data("thread_id").asLong)
        val mmsConvs: Map[Long, Seq[Message]] =
          mmsByThread.mapValues { records =>
            records.sortBy(_.data("date").asLong).flatMap { row =>
              typeByFlags(row.data("msg_box").asLong).map { tpe =>
                val msg =
                  SimpleMessage(
                    row.data("body").asString,
                    tpe,
                    if (tpe == Received) Some(row.data("address").asString) else None,
                    row.data("date").asLong
                  )

                parts.find(_.data("mid") == row.data("_id")) match {
                  case Some(part) =>
                    MediaMessage(
                      msg,
                      Attachment(part.data("unique_id").asLong, part.data("file_name").asString, part.data("ct").asString)
                    )
                  case None =>
                    msg
                }
              }
            }
          }

        combineMaps(smsConvs, mmsConvs, Nil)((c1, c2) => (c1 ++ c2).sortBy(_.message.dateSentMillis)).toSeq.map {
          case (threadId, msgs) =>
            val recps = threadInfo(threadId)
            Conversation(recps, msgs)
        }
      }

      SignalData(conversations)
    }
  }
}
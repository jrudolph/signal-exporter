package net.virtualvoid.signal

import net.virtualvoid.signal.RecordReader.BackupRecord

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

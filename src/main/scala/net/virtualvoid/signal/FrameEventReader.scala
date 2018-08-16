package net.virtualvoid.signal

import net.virtualvoid.signal.RawFrameReader.RawBackupEventConsumer

sealed trait BackupFrameEvent extends Product
object BackupFrameEvent {
  final case class DatabaseVersion(version: Int) extends BackupFrameEvent
  final case class SharedPreference(file: String, key: String, value: String) extends BackupFrameEvent
  final case class Avatar(name: String, data: Array[Byte]) extends BackupFrameEvent
  sealed trait SqlParameter extends Product {
    def asString: String = notConvertible("String")
    def asLong: Long = notConvertible("Long")

    private def notConvertible(to: String): Nothing =
      throw new IllegalArgumentException(s"$productPrefix cannot be converted to $to")
  }
  final case class StringParameter(value: String) extends SqlParameter {
    override def asString: String = value
  }
  final case class IntParameter(value: Long) extends SqlParameter {
    override def asLong: Long = value
  }
  final case class DoubleParameter(value: Double) extends SqlParameter
  final case class BlobParameter(data: Array[Byte]) extends SqlParameter
  final case object NullParameter extends SqlParameter {
    override def asString: String = ""
  }

  final case class SqlStatement(statement: String, parameters: Seq[SqlParameter]) extends BackupFrameEvent
  final case class Attachment(rowId: Long, attachmentId: Long, data: Array[Byte]) extends BackupFrameEvent
  final case object End extends BackupFrameEvent
}

object FrameEventReader {
  object FrameEventConsumer {
    def apply[T](_initial: T)(_step: (T, BackupFrameEvent) => T): RawBackupEventConsumer[T] =
      new RawFrameReader.RawBackupEventConsumer[T] {
        val lifted = liftToRaw(_step)

        override def initial: T = _initial
        override def step(current: T, event: RawBackupEvent): T = lifted(current, event)
      }
  }

  private def liftToRaw[T](f: (T, BackupFrameEvent) => T): (T, RawBackupEvent) => T = { (t, event) =>
    import BackupFrameEvent._
    import RawBackupEvent._

    val richEvent =
      event match {
        case FrameEvent(frame) =>
          if (frame.hasVersion)
            DatabaseVersion(frame.getVersion.getVersion)
          else if (frame.hasPreference) {
            val pref = frame.getPreference
            SharedPreference(pref.getFile, pref.getKey, pref.getValue)
          } else if (frame.hasStatement) {
            val stmt = frame.getStatement
            import scala.collection.JavaConverters._
            val params = stmt.getParametersList.asScala.map { param =>
              if (param.hasStringParamter)
                StringParameter(param.getStringParamter)
              else if (param.hasIntegerParameter)
                IntParameter(param.getIntegerParameter)
              else if (param.hasDoubleParameter)
                DoubleParameter(param.getDoubleParameter)
              else if (param.hasBlobParameter)
                BlobParameter(param.getBlobParameter.toByteArray)
              else if (param.hasNullparameter)
                NullParameter
              else
                throw new IllegalStateException(s"Unexpected SQL parameter: $param")
            }.toVector
            SqlStatement(stmt.getStatement, params)
          } else if (frame.hasEnd)
            End
          else
            throw new IllegalStateException(s"Unexpected event: $event")

        case FrameEventWithAttachment(frame, attachmentData) =>
          if (frame.hasAttachment) {
            val attachment = frame.getAttachment
            Attachment(attachment.getRowId, attachment.getAttachmentId, attachmentData)
          } else if (frame.hasAvatar) {
            val avatar = frame.getAvatar
            Avatar(avatar.getName, attachmentData)
          } else throw new IllegalStateException(s"Unexpected event with attachment: $attachmentData")

      }
    f(t, richEvent)
  }
}

package net.virtualvoid.signal

import java.io.File
import java.io.FileOutputStream
import java.util.Date

import BackupFrameEvent.SqlParameter
import DataModel.SignalData
import FrameEventReader.FrameEventConsumer
import RawFrameReader.RawBackupEventConsumer
import RecordReader.BackupRecord
import RecordReader.RecordConsumer

import scala.collection.mutable.ListBuffer

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

  val RetrieveRecords: RawBackupEventConsumer[List[BackupRecord]] =
    RecordConsumer(ListBuffer.empty[BackupRecord], (buffer: ListBuffer[BackupRecord], record) => buffer += record)(_.result)

  val PrintRecordHeuristics =
    RetrieveRecords.andThen { records =>
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

  val BuildModel: RawBackupEventConsumer[SignalData] =
    RetrieveRecords.andThen(DataModel.convertRecordsToModel)

  val ExportToJson =
    BuildModel.andThen { model =>
      import DataModel.DataModelFormat._
      import spray.json._

      val output = new FileOutputStream("data.json")
      output.write(model.toJson.prettyPrint.getBytes("utf8"))
      output.close()
    }

  val ExportToHtml =
    BuildModel.andThen { model =>
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
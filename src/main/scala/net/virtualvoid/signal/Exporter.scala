package net.virtualvoid.signal

import java.io.{ File, FileInputStream, FileOutputStream }
import java.security.MessageDigest

import org.thoughtcrime.securesms.backup.BackupProtos.{ Attachment, BackupFrame }

import scala.io.Source

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
  val pass = Source.fromFile(passFile).mkString.replaceAll("\\s", "")
  require(pass.length == 30, s"Passphrase must have 30 characters but had ${pass.length}")

  val attachmentsDir = existingFile("Attachments dir", "attachments")

  val attachmentCacheDir = existingFile("Attachments cache dir", "attachments-cache")

  def main(args: Array[String]): Unit =
    try {
      // TODO: call operations
      //Operations.ExportToHtml.run(backupFile, pass)
      //Operations.PrintFrameTypeHisto.run(backupFile, pass)

      import sys.process._
      def fileInfoContains(file: File, cands: String*): Boolean =
        fileInfoMatches(file, p => cands.exists(p.contains))
      def fileInfoMatches(file: File, p: String => Boolean): Boolean =
        p(s"file ${file.getAbsolutePath}".!!)

      val downsizeImage = Operation(
        "downsize1mp70p",
        fileInfoContains(_, "JPEG", "PNG"),
        { (orig, target, hash) =>
          val cmdLine = s"""convert -resize 1000000@> -quality 70% -format jpeg "${orig.getAbsolutePath}" "${target.getAbsolutePath}""""
          println(s"Running [$cmdLine]")
          cmdLine.!
        }
      )
      val downsizeVideo = Operation(
        "downsizevideo24fps720px265crf30withmeta",
        fileInfoContains(_, "MP4", "3GPP"),
        { (orig, target, hash) =>
          val cmdLine = s"""ffmpeg -i "${orig.getAbsolutePath}" -vf "scale='min(720,iw)':-2" -f mp4 -r 24 -vcodec libx265 -crf 30 -map_metadata 0 -movflags use_metadata_tags -metadata signal_original_hash='$hash' "${target.getAbsolutePath}""""
          println(s"Running [$cmdLine]")
          cmdLine.!
        }
      )
      val newFile = new File("newfile.bin")
      RawFrameReader.writeEvents(newFile, pass,
        RawFrameReader.rawEventIterator(backupFile, pass)
          .map {
            case fe: RawBackupEvent.FrameEvent => fe
            case fe @ RawBackupEvent.FrameEventWithAttachment(frame, att) =>
              if (frame.hasAttachment) {
                val res = runOps(Seq(downsizeImage, downsizeVideo), att)

                if (res.length < att.length) {
                  println(f"Downsized ${frame.getAttachment.getAttachmentId} from ${att.size} to ${res.size} (${res.size.toDouble / att.length * 100}%4.1f %%)")

                  val newFrame =
                    BackupFrame.newBuilder(frame)
                      .setAttachment {
                        Attachment.newBuilder(frame.getAttachment)
                          .setLength(res.length)
                      }
                      .build()

                  RawBackupEvent.FrameEventWithAttachment(newFrame, res)
                } else {
                  println(f"${Console.RED}Operation increased file size${Console.RESET} ${frame.getAttachment.getAttachmentId} from ${att.size} to ${res.size} (${res.size.toDouble / att.length * 100}%4.1f %%) keeping old")
                  fe
                }
              } else fe
          }
      )
      println("Finished writing")
      Operations.PrintFrameTypeHisto.run(newFile, pass)
    } catch {
      case x: Throwable => x.printStackTrace()
    }

  case class Operation(short: String, isApplicable: File => Boolean, run: (File, File, String) => Unit)

  def runOps(ops: Seq[Operation], att: Array[Byte]): Array[Byte] = {
    val hash = sha256(att)
    val f = ensureInCache(hash, att)
    ops.find(_.isApplicable(f)) match {
      case Some(op) =>
        val targetFile = convertedCacheFile(hash, op)
        if (!targetFile.exists()) op.run(f, targetFile, toHexAscii(hash))
        load(targetFile)
      case _ =>
        att
    }
  }

  def sha256(bs: Array[Byte]): Array[Byte] = {
    val md = MessageDigest.getInstance("SHA-256")
    md.digest(bs)
  }
  def toHexAscii(bs: Array[Byte]): String =
    bs.map(_ formatted "%02x").mkString

  val origDataDir = new File(attachmentCacheDir, "original")
  val convertedDataDir = new File(attachmentCacheDir, "converted")
  def origCacheFile(hash: Array[Byte]): File = {
    val hex = toHexAscii(hash)
    val res = new File(origDataDir, s"${hex.take(2)}/${hex.drop(2)}")
    res.getParentFile.mkdirs()
    res
  }
  def convertedCacheFile(hash: Array[Byte], op: Operation): File = {
    val hex = toHexAscii(hash)
    val res = new File(convertedDataDir, s"${op.short}/${hex.take(2)}/${hex.drop(2)}")
    res.getParentFile.mkdirs()
    res
  }
  def ensureInCache(hash: Array[Byte], data: Array[Byte]): File = {
    val origFile = origCacheFile(hash)
    if (origFile.exists()) origFile
    else {
      val fos = new FileOutputStream(origFile)
      fos.write(data)
      fos.close()
      origFile
    }
  }
  val buffer = new Array[Byte](300000000)
  def load(f: File): Array[Byte] = {
    val fis = new FileInputStream(f)
    val read = fis.read(buffer)
    require(read < buffer.length)
    buffer.take(read)
  }
}
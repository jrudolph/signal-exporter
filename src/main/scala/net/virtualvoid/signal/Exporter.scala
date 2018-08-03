package net.virtualvoid.signal

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.thoughtcrime.securesms.backup.BackupProtos
import org.thoughtcrime.securesms.backup.BackupProtos.BackupFrame
import org.whispersystems.libsignal.kdf.HKDFv3

import scala.annotation.tailrec
import scala.io.Source

object Exporter extends App {
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

  // dump data
  // BackupReader.foldRawEvents(backupFile, pass, ())(BackupReader.dumpDataAndAttachments(attachmentsDir))

  // print events
  /*BackupReader.foldRawEvents(backupFile, pass, ())(BackupReader.foldBackupFrameEvents { (_, event) =>
    println(event)
  })*/

  val histo =
    BackupReader.foldRawEvents(backupFile, pass, Map.empty[String, Int])(BackupReader.foldBackupFrameEvents(BackupReader.dataTypeHistogram))

  histo.toSeq.sortBy(-_._2).foreach {
    case (tag, count) =>
      println(f"$count%5d $tag%s")
  }
}

object BackupReader {
  sealed trait RawBackupEvent
  object RawBackupEvent {
    final case class FrameEvent(frame: BackupFrame) extends RawBackupEvent
    final case class FrameEventWithAttachment(frame: BackupFrame, attachmentData: Array[Byte]) extends RawBackupEvent
  }

  def foldRawEvents[T](backupFile: File, password: String, initialT: T)(f: (T, RawBackupEvent) => T): T = {
    val fis = new FileInputStream(backupFile)
    val pass = password.trim.replaceAll(" ", "")

    val headerReader = new PlainInputStreamReader(fis)
    val header = headerReader.readPlainFrame().getHeader

    val salt = if (header.hasSalt) header.getSalt.toByteArray else null
    val keys = getBackupKey(pass, salt)

    val derived = new HKDFv3().deriveSecrets(keys, "Backup Export".getBytes(), 64)
    val cipherKey = derived.take(32)
    val macKey = derived.drop(32)
    val cipher = Cipher.getInstance("AES/CTR/NoPadding")

    val cipherSetup = CipherSetup(cipher, cipherKey)
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(macKey, "HmacSHA256"))

    val iv = header.getIv.toByteArray

    val reader = new EncryptedInputStreamReader(fis, cipherSetup)

    @tailrec
    def readNext(iv: Array[Byte], t: T): T =
      if (fis.available() > 0) {
        val (event, nextIv) = reader.readSecretFrame(iv)
        val newT = f(t, event)
        readNext(nextIv, newT)
      } else t

    readNext(iv, initialT)
  }

  sealed trait BackupFrameEvent extends Product
  object BackupFrameEvent {
    final case class DatabaseVersion(version: Int) extends BackupFrameEvent
    final case class SharedPreference(file: String, key: String, value: String) extends BackupFrameEvent
    final case class Avatar(name: String, data: Array[Byte]) extends BackupFrameEvent
    trait SqlParameter
    final case class StringParameter(value: String) extends SqlParameter
    final case class IntParameter(value: Long) extends SqlParameter
    final case class DoubleParameter(value: Double) extends SqlParameter
    final case class BlobParameter(data: Array[Byte]) extends SqlParameter
    final case object NullParameter extends SqlParameter

    final case class SqlStatement(statement: String, parameters: Seq[SqlParameter]) extends BackupFrameEvent
    final case class Attachment(rowId: Long, attachmentId: Long, data: Array[Byte]) extends BackupFrameEvent
    final case object End extends BackupFrameEvent
  }
  def foldBackupFrameEvents[T](f: (T, BackupFrameEvent) => T): (T, RawBackupEvent) => T = { (t, event) =>
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

  def dumpDataAndAttachments(attachmentsDir: File)(u: Unit, event: RawBackupEvent): Unit = event match {
    case RawBackupEvent.FrameEvent(frame) => println(frame)
    case RawBackupEvent.FrameEventWithAttachment(frame, attachmentData) =>
      val fileName =
        if (frame.hasAttachment) s"att-${frame.getAttachment.getAttachmentId}"
        else if (frame.hasAvatar) s"avatar-${frame.getAvatar.getName}"
        else "unknown"

      println(frame)
      val out = new FileOutputStream(new File(attachmentsDir, s"$fileName.jpg"))
      out.write(attachmentData)
      out.close()
  }

  type Histogram[T] = Map[T, Int]
  def dataTypeHistogram(counts: Histogram[String], event: BackupFrameEvent): Histogram[String] = {
    val tag = event.productPrefix
    val curCount = counts.getOrElse(tag, 0)
    counts.updated(tag, curCount + 1)
  }

  case class CipherSetup(cipher: Cipher, cipherKey: Array[Byte]) {
    def decrypt(iv: Array[Byte], data: Array[Byte]): Array[Byte] = {
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cipherKey, "AES"), new IvParameterSpec(iv))
      cipher.doFinal(data)
    }
  }

  class PlainInputStreamReader(fis: InputStream) {
    def uint32BE(): Int =
      fis.read() << 24 |
        fis.read() << 16 |
        fis.read() << 8 |
        fis.read()

    def uint32BE(bytes: Array[Byte]): Int =
      (bytes(0) & 0xff) << 24 |
        (bytes(1) & 0xff) << 16 |
        (bytes(2) & 0xff) << 8 |
        (bytes(3) & 0xff)

    def uint32BE(i: Int): Array[Byte] = {
      val buf = new Array[Byte](4)
      buf(0) = (i >> 24).toByte
      buf(1) = ((i >> 16) & 0xff).toByte
      buf(2) = ((i >> 8) & 0xff).toByte
      buf(3) = (i & 0xff).toByte

      buf
    }

    def bytes(count: Int): Array[Byte] = {
      val buf = new Array[Byte](count)
      fis.read(buf)
      buf
    }

    def readPlainFrame(): BackupFrame = {
      val len = uint32BE()
      val frameData = bytes(len)
      val frame = BackupProtos.BackupFrame.parseFrom(frameData)
      frame
    }
  }

  class EncryptedInputStreamReader(fis: InputStream, cipherSetup: CipherSetup) extends PlainInputStreamReader(fis) {
    def nextIv(iv: Array[Byte]): Array[Byte] = {
      val i = uint32BE(iv) + 1
      val res = iv.clone()
      res(0) = (i >> 24).toByte
      res(1) = (i >> 16).toByte
      res(2) = (i >> 8).toByte
      res(3) = i.toByte
      res
    }

    def readSecretFrame(iv: Array[Byte]): (RawBackupEvent, Array[Byte]) = {
      val len = uint32BE()
      val encFrameData = bytes(len - 10)
      val mac = bytes(10)
      val plainFrameData = cipherSetup.decrypt(iv, encFrameData)
      val frame = BackupProtos.BackupFrame.parseFrom(plainFrameData)

      val extraDataLength =
        if (frame.hasAttachment)
          frame.getAttachment.getLength
        else if (frame.hasAvatar)
          frame.getAvatar.getLength
        else -1

      if (extraDataLength >= 0) {
        val attIv = nextIv(iv)
        val encAtt = bytes(extraDataLength)
        val attMac = bytes(10)
        val plainAtt = cipherSetup.decrypt(attIv, encAtt)

        (RawBackupEvent.FrameEventWithAttachment(frame, plainAtt), nextIv(attIv))
      } else
        (RawBackupEvent.FrameEvent(frame), nextIv(iv))
    }
  }

  def getBackupKey(passphrase: String, salt: Array[Byte]): Array[Byte] = {
    val digest = MessageDigest.getInstance("SHA-512")
    if (salt != null) digest.update(salt)

    val input = passphrase.getBytes("ASCII")

    @tailrec
    def nextRound(hash: Array[Byte], remaining: Int): Array[Byte] =
      if (remaining == 0) hash
      else {
        digest.update(hash)
        val newHash = digest.digest(input)
        nextRound(newHash, remaining - 1)
      }

    nextRound(input, 250000)
      .take(32)
  }
}
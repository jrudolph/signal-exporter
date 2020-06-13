package net.virtualvoid.signal

import java.io.File

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

  def main(args: Array[String]): Unit =
    try {
      // TODO: call operations

    } catch {
      case x: Throwable => x.printStackTrace()
    }
}
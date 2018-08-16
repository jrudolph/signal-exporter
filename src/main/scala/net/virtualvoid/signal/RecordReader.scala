package net.virtualvoid.signal

import net.virtualvoid.signal.FrameEventReader.FrameEventConsumer
import net.virtualvoid.signal.RawFrameReader.RawBackupEventConsumer

object RecordReader {
  object RecordConsumer {
    def apply[T, U](initial: T, step: (T, BackupRecord) => T)(finalStep: T => U): RawBackupEventConsumer[U] =
      FrameEventConsumer.withFinalStep(
        State(Map.empty, initial),
        (state, event) => recordReader(step)(state, event)
      ) { state => finalStep(state.t) }
  }

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

  private final case class State[T](tableMetadata: Map[String, TableMetadata], t: T)
  val CreateTable = """CREATE TABLE (\w+) \(([^)]*)\)""".r
  val FieldSpec = """\s*(\w+) (\w+)(?: (.*))?""".r
  val Insert = """INSERT INTO (\w+) VALUES \([?,]*\)""".r
  private def recordReader[T](f: (T, BackupRecord) => T)(state: State[T], event: BackupFrameEvent): State[T] = event match {
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
}

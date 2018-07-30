val scalaV = "2.12.6"
val specs2V = "4.3.2"

enablePlugins(ProtobufPlugin)

libraryDependencies ++= Seq(
  "org.whispersystems" % "signal-protocol-java" % "2.6.2",

  "org.specs2" %% "specs2-core" % specs2V % "test"
)

scalaVersion := scalaV

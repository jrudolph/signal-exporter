# Signal Encrypted Backup Exporter

The [Signal Android App](https://github.com/signalapp/Signal-Android) allows creating backups in a custom encrypted format. In the current version
this is the only simple way to export the full database (without requiring root). It is currently impossible to export all media files from signal
in plaintext. This has proven to make Signal a poor choice for day-to-day communications because 1. the Signal database starts spamming internal
memory quickly and 2. you cannot "free" memory easily because there's no way to quickly export (and then delete) media files (or just find out
what the worst offending media files are).
   
Right now this project provides example code in Scala to decrypt the Signal backup and dump all media files to disk.

## Future ideas

 * provide library to read backup
 * export conversations as HTML
 * filter DB for reimporting into Signal (might be hard to keep internal db consistency)
 * optimize old media files for low disk usage 

## Other tools

 * [signal-back](https://github.com/xeals/signal-back): Backup reader implemented in Go
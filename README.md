# nmap2db.rb
This is a (collection of scripts) that will convert nmap *.xml output to various formats.
## nmap2sqlite.rb
Parses nmap XML scan data and creates/updates sqlite3 database.

```
./nmap2sqlite.rb [-i|--input] <input file> [-d|--database] <path/to/database/file> [-h|--help] [-v|--verbose] [-q|--quiet]

-i|--input                      Specifies the full path to the nmap XML input file.
-d|--database                   Specifies the full path to the database to be created/updated.
-h|--help                       Displays this helpful message, and exits.
-v|--verbose                    Displays more output than normal.
-q|--quiet                      Displays less output than normal.

```
## nmap2csv.rb
Parses nmap XML scan data and outputs to CSV (default) or Excel binary format(s).

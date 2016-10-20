# nmap2db.rb
[![Code Climate](https://codeclimate.com/github/d4t4king/nmap2db.rb/badges/gpa.svg)](https://codeclimate.com/github/d4t4king/nmap2db.rb) [![Test Coverage](https://codeclimate.com/github/d4t4king/nmap2db.rb/badges/coverage.svg)](https://codeclimate.com/github/d4t4king/nmap2db.rb/coverage) [![Issue Count](https://codeclimate.com/github/d4t4king/nmap2db.rb/badges/issue_count.svg)](https://codeclimate.com/github/d4t4king/nmap2db.rb)

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

```
./nmap2csv.rb [-i|--input] <input file> [-o|--output] <path/to/csv/file> [-h|--help] [-v|--verbose] [-q|--quiet]

-i|--input                      Specifies the full path to the nmap XML input file.
-0|--output                     Specifies the full path to the csv to be created.
-h|--help                       Displays this helpful message, and exits.
-v|--verbose                    Displays more output than normal.
-q|--quiet                      Displays less output than normal.
-E|--excel                      Writes the output to am Excel spreadsheet/workbook, rather than the
                                        simpler CSV format.
-U|--up                         Only print/write data for hosts that are "up".

```

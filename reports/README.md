# nmap2ew.rb
Script to prep Eyewitness gathering script from a nmap scan XML file.

```
./nmap2ew.rb [-h|--help] [-i|--input] <input_file> [-d|--database] </path/to/database/file> [-b|--binary[

-h|--help                       Display this useful help message
-i|--input                      Parse the supplied input file for hosts/URLs.  
-d|--database                   Query targets from the specified sqlite/nmap database.  Expects the schema
                                defined in other scripts in this repo.
-b|--binary                     Path to the eyewitness script/binary, in case not in expected location.
                                Expected location is in /usr/bin/(eyewitness).  *The file is not actually likelt
                                to be a binary, but a Python script.  It doesn't really matter, so long 
                                as the python script acts like a binary.
```

# ports_report.rb
Generate a ports report from a sqlite3 database.

```

./ports_report.rb --help|-h --verbose|-v --database|-d <database_file> --output|-o <output_file.pdf>

--help|-h                       Display this useful message
--verbose|-v                    Display more verbose output.  Usually used for debugging.
--database|-d                   Specify the database file from which to draw data for the report.
--output|-o                     Specify the output file.  This program currently only supports PDF
                                file format as output.

```


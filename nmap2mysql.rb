#!/usr/bin/env ruby

###############################################################################
#
#	Script:			nmap2mysql.rb
#
#	Author:			Charlie Heselton aka "dataking" <dataking [at] gmail [dot] com>
#
#	Date:			7/21/2016
#
#	Version:		0.1
#
#	Description:	This script will take an XML file from nmap output, and
#		enter it into the (default) database.
#
#	TODO:
#		* Expand verbose/quiet to "degrees of verbosity/silence"
#
###############################################################################

require 'rubygems'
require 'colorize'
require 'pp'
require 'nmap/parser'
require 'getoptlong'
require 'dbi'

opts = GetoptLong.new(
	['--input', '-i', GetoptLong::REQUIRED_ARGUMENT ],
	['--database', '-d', GetoptLong::REQUIRED_ARGUMENT ],
	['--verbose', '-v', GetoptLong::NO_ARGUMENT ],
	['--quiet', '-q', GetoptLong::NO_ARGUMENT ],
	['--help', '-h', GetoptLong::NO_ARGUMENT ],
	['--host', '-H', GetoptLong::REQUIRED_ARGUMENT ],
	['--user', '-u', GetoptLong::REQUIRED_ARGUMENT ],
	['--pass', '-p', GetoptLong::REQUIRED_ARGUMENT ],
)

def usage(noexit=false)
	puts <<-END

#{$0} [-i|--input] <input file> [-d|--database] <database> [-H|--host] <db_hostname> [-u|--user] <db_username> [-p|--pass] <db_password>
		[-h|--help] [-v|--verbose] [-q|--quiet]

-i|--input				Specified the full path to the nmap XML input file.
-d|--database				Specifies the name of the mysql database.  Creates it, if it does not exist.
-H|--host				Specifies the name of the mysql host.
-u|--user				Specifies the name of the user for the mysql database.
-p|--pass				Specifies the password for the user specified with '-u'
-h|--help				Displays this helpful message, and exits.
-v|--verbose				Displays more output than normal.
-q|--quiet				Displays less output than normal (or none at all).

END

	unless noexit
		exit 1
	end
end

input = ''; @verbose = false; @quiet = false
help = ''
@database = ''; @host = ''; @user = ''; @pass = ''
opts.each do |opt,arg|
	case opt
	when '--input'
		input = arg
	when '--database'
		@database = arg
	when '--host'
		@host = arg
	when '--user'
		@user = arg
	when '--pass'
		@pass = arg
	when '--verbose'
		verbose = true
	when '--quiet'
		quiet = true
	when '--help'
		usage()
	end
end

if @verbose && @quiet
	raise "Can't be verbose and quiest at the same time.  Pick one."
end

if @verbose
	puts <<-END

###############
# Input file:	#{input}
# Database:		#{@host}:#{@database}:#{@user}
###############

END

end

def create_nmap_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{host}:#{db}", username, passwd)
	if @verbose; print "Creating the nmap table....".yellow; end
	rtv = dbh.do("CREATE TABLE IF NOT EXIST nmap (sid INT NOT NULL AUTO_INCREMENT, version VARCHAR(8), xmlversion VARCHAR(8), args VARCHAR(255), types VARCHAR(255), starttime DATETIME, startstr VARCHAR(255), endtime DATETIME, endstr VARCHAR(255), numservices INT), PRIMARY KEY (sid)")
	if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
	return rtv
end

def create_hosts_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql#{db}", host, username, passwd)
	if @verbose; print "Creating the host table....".yellow; end
	rtv = dbh.do("CREATE TABLE IF NOT EXIST hosts (sid INT, hid INT NOT NULL AUTO_INCREMENT, ip4 VARCHAR(16), ip4num VARCHAR(255), hostname VARCHAR(255), status VARCHAR(255), tcpcount INT, udpcount INT, mac VARCHAR(24), vendor VARCHAR(255), ip6 VARCHAR(64), distance INT, uptime VARCHAR(255), upstr VARCHAR(255)), PRIMARY_KEY(hid)")
	if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
end

def create_seq_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}", host, username, passwd)
	if @verbose; print "Creating the sequencing table....".yellow; end
	rtv = dbh.do("CREATE TABLE IF NOT EXIST sequencing (hid INT, tcpclass VARCHAR(255), tcpindex VARCHAR(255), tcpvalues VARCHAR(255), ipclass VARCHAR(255), ipvalues VARCHAR(255), tcptclass VARCHAR(255), tcptvalues VARCHAR(255))")
	if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
end

def create_ports_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}", host, username, passwd)
	rtv = dbh.do("CREATE TABLE IF NOT EXIST ports (hid INT, port INT, type VARCHAR(255), state VARCHAR(255), name VARCHAR(255), tunnel VARCHAR(255), product VARCHAR(255), version VARCHAR(255), extra VARCHAR(255), confidence INT, method VARCHAR(255), proto VARCHAR(255), owner VARCHAR(255), rpcnum VARCHAR(255), fingerprint TEXT)")
	if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
end

def create_os_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}", host, username, passwd)
	rtv = dbh.do("CREATE TABLE IF NOT EXIST os (hid INT, name VARCHAR(255), family VARCHAR(255), generation VARCHAR(255), type VARCHAR(255), vendor VARCHAR(255), accuracy INT)")
	if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
end

def create_database(db=@database,host=@host,username=@user,passwd=@pass)
	create_nmap_table(@database, @host, @user, @pass)
	create_hosts_table(@database, @host, @user, @pass)
	create_seq_table(@database, @host, @user, @pass)
	create_ports_table(@database, @host, @user, @pass)
	create_os_table(@database, @host, @user, @pass)

	return true
end

def check_scan_record(_args, _starttime, _endtime)
	dbh = DBI.connect("DBI:Mysql:#{@database}", host, user, pass)
	stmt = dbh.do("SELECT sid FROM nmap WHERE args='#{_args}' AND starttime='#{_starttime}' AND endtime='#{_endtime}'")
	stmt.execute
	while row=sth.fetch do
		if row[0].nil? || row[0] == ''
			return false
		else
			return row[0]
		end
	end
end

nmap = Nmap::Parser.new
if File.exists?(input) && !File.directory?(input) && !File.zero?(input)
	nmap.parsefile(input)
else
	usage(true)
	if !File.exists?(input)
		raise "Input file (#{input}) doesn't exist or not specified.  Nothing to do."
	elsif File.directory?(input)
		raise "Input file (#{input}) appears to be a directory.  I don't know how to handle those (yet)."
	elsif File.zero?(input)
		raise "Input file (#{input}) appears to be zero (0) bytes.  Nothing to do."
	else
		raise "Unhandled error for input file (#{input})."
	end
end

create_database(@database, @host, @user, @pass)

sid = check_scan_record(nmap.session.scan_args, nmap.session.start_time.to_s, nmap.session.stop_time.to_s)
if sid.is_a?(Integer) && sid > 0
	puts "Scan record already exists.  SID = '#{sid}'" unless @quiet
else
	sql1 = "INSERT INTO nmap (version, xmlversion, args, types, starttime, startstr, endtime, endstr, numservices) VALUES (?,?,?,?,?,?,?,?,?)"
	puts "SQL1: #{sql1}".yellow if @verbose
	rtv = dbh.do(sql, nmap.session.nmap_version, nmap.session.xml_version, nmap.session.scan_args, nmap.session.scan_types, nmap.session.start_time.to_s, nmap.session.stop_time.to_s, nmap.session.stop_str, nmap.session.numservices)
	sid = check_scan_record(nmap.session.scan_args, nmap.session.start_time.to_s, nmap.session/stop_time.to_s)
end

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
	dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
	if @verbose; print "Creating the nmap table....".yellow; end
	rtv = dbh.do("CREATE TABLE IF NOT EXISTS nmap (sid INT NOT NULL AUTO_INCREMENT, version VARCHAR(8), xmlversion VARCHAR(8), args VARCHAR(255), types VARCHAR(255), starttime DATETIME, startstr VARCHAR(255), endtime DATETIME, endstr VARCHAR(255), numservices INT, PRIMARY KEY (sid))")
	if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
	dbh.disconnect
	return rtv
end

def create_hosts_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
	if @verbose; print "Creating the host table....".yellow; end
	rtv = dbh.do("CREATE TABLE IF NOT EXISTS hosts (sid INT, hid INT NOT NULL AUTO_INCREMENT, ip4 VARCHAR(16), ip4num VARCHAR(255), hostname VARCHAR(255), status VARCHAR(255), tcpcount INT, udpcount INT, mac VARCHAR(24), vendor VARCHAR(255), ip6 VARCHAR(64), distance INT, uptime VARCHAR(255), upstr VARCHAR(255), PRIMARY KEY(hid))")
	if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
	dbh.disconnect
	return rtv
end

def create_seq_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
	if @verbose; print "Creating the sequencing table....".yellow; end
	rtv = dbh.do("CREATE TABLE IF NOT EXISTS sequencing (hid INT, tcpclass VARCHAR(255), tcpindex VARCHAR(255), tcpvalues VARCHAR(255), ipclass VARCHAR(255), ipvalues VARCHAR(255), tcptclass VARCHAR(255), tcptvalues VARCHAR(255))")
	if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
	dbh.disconnect
	return rtv
end

def create_ports_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
	if @verbose; print "Creating the ports table....".yellow; end
	rtv = dbh.do("CREATE TABLE IF NOT EXISTS ports (hid INT, port INT, type VARCHAR(255), state VARCHAR(255), name VARCHAR(255), tunnel VARCHAR(255), product VARCHAR(255), version VARCHAR(255), extra VARCHAR(255), confidence INT, method VARCHAR(255), proto VARCHAR(255), owner VARCHAR(255), rpcnum VARCHAR(255), fingerprint TEXT)")
	if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
	dbh.disconnect
	return rtv
end

def create_os_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
	if @verbose; print "Creating the os table....".yellow; end
	rtv = dbh.do("CREATE TABLE IF NOT EXISTS os (hid INT, name VARCHAR(255), family VARCHAR(255), generation VARCHAR(255), type VARCHAR(255), vendor VARCHAR(255), accuracy INT)")
	if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
	dbh.disconnect
	return rtv
end

def create_database(db=@database,host=@host,username=@user,passwd=@pass)
	begin
		dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
		if @verbose; "Creating the database....".yellow; end
		rtv = dbh.do("CREATE DATABASE IF NOT EXISTS #{db}")
		if @verbose; puts "|#{rtv.length.to_s}|#{$!}|".red; end
		dbh.disconnect
	rescue DBI::DatabaseError => e
		if e.message =~ /Unknown database \'#{db}\'/
			raise "Looks like the #{db} database doesn't exist yet, and we don't know how to create it."
		end
	end
	rtv = create_nmap_table(@database, @host, @user, @pass)
	if @verbose; puts "create_nmap_table:RTV: #{rtv.to_s}".red; end
	rtv = create_hosts_table(@database, @host, @user, @pass)
	if @verbose; puts "create_hosts_table:RTV: #{rtv.to_s}".red; end
	rtv = create_seq_table(@database, @host, @user, @pass)
	if @verbose; puts "create_seq_table:RTV: #{rtv.to_s}".red; end
	rtv = create_ports_table(@database, @host, @user, @pass)
	if @verbose; puts "create_ports_table:RTV: #{rtv.to_s}".red; end
	rtv = create_os_table(@database, @host, @user, @pass)
	if @verbose; puts "create_os_table:RTV: #{rtv.to_s}".red; end

	return rtv
end

def check_scan_record(_args, _starttime, _endtime)
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	stmt = dbh.prepare("SELECT sid FROM nmap WHERE args='#{_args}' AND starttime='#{_starttime}' AND endtime='#{_endtime}'")
	stmt.execute
	while row=stmt.fetch do
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

dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
sid = check_scan_record(nmap.session.scan_args, nmap.session.start_time.to_s, nmap.session.stop_time.to_s)
if sid.is_a?(Integer) && sid > 0
	puts "Scan record already exists.  SID = '#{sid}'" unless @quiet
else
	sql1 = "INSERT INTO nmap (version, xmlversion, args, types, starttime, startstr, endtime, endstr, numservices) VALUES (?,?,?,?,?,?,?,?,?)"
	puts "SQL1: #{sql1}".yellow if @verbose
	if @verbose
		pp nmap.session.inspect.to_s.green
	end
	rtv = dbh.do(sql1, nmap.session.nmap_version, nmap.session.xml_version, nmap.session.scan_args, nmap.session.scan_types, nmap.session.start_time.to_s, nmap.session.start_str, nmap.session.stop_time.to_s, nmap.session.stop_str, nmap.session.numservices)
	sid = check_scan_record(nmap.session.scan_args, nmap.session.start_time.to_s, nmap.session.stop_time.to_s)
end

if nmap.hosts.nil? || nmap.hosts.length == 0
    puts "There are no hosts in this scan." unless @quiet
else
	puts "Found hosts in scan." unless @quiet
	nmap.hosts do |host|
		hid = dbh.select_one("SELECT hid FROM hosts where ip4='#{host.ip4_addr.to_s}'")
		puts "HID = #{hid}" if @verbose
=begin
		if hid.is_a?(Integer) && hid > 0
			s = db.execute("SELECT sid,hid FROM hosts WHERE sid='#{sid}' AND hid='#{hid}'")
			s.flatten!
			if s[0] == sid && s[1] == hid
				puts "Scan and host already exist.  Skipping." unless @quiet
				next
			end     # if sid && hid
			# hid exists, but sid is different, so different hid (the way this db is structured).
		end     # if hid(int)
		
		sql2 = %{INSERT INTO hosts (sid, ip4, ip4num, hostname, status, tcpcount, 
			udpcount, mac, vendor, ip6, distance, uptime, upstr) VALUES ('#{sid}', 
			'#{host.ip4_addr}', '[ip4num]', '#{host.hostname}', '#{host.status}', 
			'#{host.getports(:tcp).length.to_s}', '#{host.getports(:udp).length.to_s}', 
			'#{host.mac_addr}', '#{host.mac_vendor}', '#{host.ip6_addr}', 
			'#{host.distance.to_s}', '#{host.uptime_seconds.to_s}', 
			'#{host.uptime_lastboot}')}.gsub(/(\t|\s)+/, " ").strip
		puts "SQL2: #{sql2}".green if @verbose
		db.execute(sql2)
		puts "Host record inserted." unless @quiet
		hid = db.execute("SELECT hid FROM hosts where ip4='#{host.ip4_addr.to_s}' AND sid='#{sid}'")
		if hid.is_a?(Array)
			if hid[0].is_a?(Array)
				hid.flatten!
				if hid.length > 1
					puts "(2) Got more than one value for hid lookup.  Truncate DB." unless @quiet
				else
					hid = hid[0]
				end
			end
		end
		if hid
			#puts "#{hid}".green
			sql3 = %{INSERT INTO sequencing (hid, tcpclass, tcpindex, tcpvalues,
				ipclass, ipvalues, tcptclass, tcptvalues) VALUES ('#{hid}', 
				'#{host.tcpsequence_class}', '#{host.tcpsequence_index}', 
				'#{host.tcpsequence_values}', '#{host.ipidsequence_class}',
				'#{host.ipidsequence_values}', '#{host.tcptssequence_class}',
				'#{host.tcptssequence_values}')}.gsub(/(\t|\s)+/, " ").strip
			puts "SQL3: #{sql3}".cyan if @verbose
			db.execute(sql3)
			puts "Sequencing record inserted." unless @quiet

			[:tcp, :udp].each do |type|
				host.getports(type) do |port|
					if !port.service.fingerprint.nil? && port.service.fingerprint != ""
						port.service.fingerprint.gsub!(/\'/, "&#39;")
					end
					sql4 = %{INSERT INTO ports (hid, port, type, state, name, tunnel,
						product, version, extra, confidence, method, proto, owner, 
						rpcnum, fingerprint) VALUES ('#{hid}', '#{port.num}', '',
						'#{port.state}', '#{port.service.name}', '#{port.service.tunnel}',
						'#{port.service.product}', '#{port.service.version}', 
						'#{port.service.extra}', '#{port.service.confidence}',
						'#{port.service.method}', '#{port.service.proto}',
						'#{port.service.owner}', '#{port.service.rpcnum}',
						'#{port.service.fingerprint}')}.gsub(/(\t|\s)+/, " ").strip
					puts "#{sql4}".green if @verbose
					db.execute(sql4)
					puts "Port record inserted." unless @quiet
				end     # host.getports()
			end     # port types

			sql5 = %{INSERT INTO os (hid, name, family, generation, type, vendor,
				accuracy) VALUES ('#{hid}', '#{host.os.name}', '#{host.os.osfamily}',
				'#{host.os.osgen}', '#{host.os.ostype}', '#{host.os.osvendor}',
				'#{host.os.class_accuracy}')}.gsub(/(\t|\s)+/, " ").strip
			puts "#{sql5}".magenta if @verbose
			db.execute(sql5)
			puts "OS record inserted." unless @quiet
		else
			raise "Got a false value for hid after record entry."
		end     # if hid
=end
	end     # nmap.hosts loop
end     # if nmap.hosts.nil?

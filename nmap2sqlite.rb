#!/usr/bin/env ruby

###############################################################################
#
#	Script:			nmap2sqlite.rb
#
#	Author:			Charlie Heselton (cheselton@semprautilities.com)
#
#	Date:			9/24/2015
#
#	Version:		0.1
#
#	Description:	This script will take an XML file from nmap output, and
#		enter it into the (default) database.
#
#	TODO:
#		* Specify database file (create schema, if it doesn't exist)
#		* Add help
#		* check if scan data already exists in DB
#
###############################################################################

require 'rubygems'
require 'colorize'
require 'pp'
require 'nmap/parser'
require 'getoptlong'
require 'sqlite3'

opts = GetoptLong.new(
	['--input', '-i', GetoptLong::REQUIRED_ARGUMENT ],
	['--database', '-d', GetoptLong::REQUIRED_ARGUMENT ],
)

input = ''
@database = 'nmap_scans.db'
opts.each do |opt,arg|
	case opt
	when '--input'
		input = arg
	when '--database'
		@database = arg
	end
end

def usage(noexit=false) 
	puts <<-EOS

$0 [-i|--input] <input file> [-d|--database] <path/to/databaxe/file>

-i|--input			Specifies the full path to the nmap XML input file.
-d|--database			Specifies the full path to the database to be creted/updated.


EOS
	unless noexit
		exit 1
	end
end

puts <<-EOS

################
# Input file:		#{input}
# Database file:	#{@database}
################

EOS

def create_nmap_table( db_file = @database )
	db = SQLite3::Database.new(db_file)
	notable = false
	r = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nmap'")
	r.flatten!
	if r[0].nil? || r[0] == ""
		notable = true
	elsif r[0] == "nmap"
		puts "nmap table exists".blue
		return 0
	else
		puts "Unexpected result:".red
		pp r
		puts
		return -1
	end

	if (notable)
		print "Creating the nmap table....".yellow
		rtv = db.execute("CREATE TABLE nmap (sid INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, xmlversion TEXT, args TEXT, types TEXT, starttime INTEGER, startstr TEXT, endtime INTEGER, endstr TEXT, numservices INTEGER)")
		puts "|#{rtv.length.to_s}|#{$!}|".red
	else
		puts "We shouldn't be here....ever.".blue.on_white.blink
		pp notable
	end
end

def create_hosts_table( db_file = @database )
	db = SQLite3::Database.new(db_file)
	notable = false
	r = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hosts'")
	r.flatten!
	if r[0].nil? || r[0] == ""
		notable = true
	elsif r[0] == "hosts"
		puts "hosts table exists".blue
		return 0
	else
		puts "Unexpected result:".red
		pp r
		puts
		return -1
	end

	if (notable)
		print "Creating the hosts table...".yellow
		rtv = db.execute("CREATE TABLE hosts (sid INTEGER, hid INTEGER PRIMARY KEY AUTOINCREMENT, ip4 TEXT, ip4num TEXT, hostname TEXT, status TEXT, tcpcount INTEGER, udpcount INTEGER, mac TEXT, vendor TEXT, ip6 TEXT, distance INTEGER, uptime TEXT, upstr TEXT)")
		puts "|#{rtv.length.to_s}|#{$!}|".red
	else
		puts "We shouldn't be here....ever.".blue.on_white.blink
		pp notable
	end
end

def create_seq_table( db_file = @database )
	db = SQLite3::Database.new(db_file)
	notable = false
	r = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sequencing'")
	r.flatten!
	if r[0].nil? || r[0] == ""
		notable = true
	elsif r[0] == "sequencing"
		puts "sequencing table exists".blue
		return 0
	else
		puts "Unexpected result:".red
		pp r
		puts
		return -1
	end

	if (notable)
		print "Creating the sequencing table...".yellow
		rtv = db.execute("CREATE TABLE sequencing (hid INTEGER, tcpclass TEXT, tcpindex TEXT, tcpvalues TEXT, ipclass TEXT, ipvalues TEXT, tcptclass TEXT, tcptvalues TEXT)")
		puts "|#{rtv.length.to_s}|#{$!}|".red
	else
		puts "We shouldn't be here....ever.".blue.on_white.blink
		pp notable
	end
end

def create_ports_table( db_file = @database )
	db = SQLite3::Database.new(db_file)
	notable = false
	r = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ports'")
	r.flatten!
	if r[0].nil? || r[0] == ""
		notable = true
	elsif r[0] == "ports"
		puts "ports table exists".blue
		return 0
	else
		puts "Unexpected result:".red
		pp r
		puts
		return -1
	end

	if (notable)
		print "Creating the ports table...".yellow
		rtv = db.execute("CREATE TABLE ports (hid INTEGER, port INTEGER, type TEXT, state TEXT, name TEXT, tunnel TEXT, product TEXT, version TEXT, extra TEXT, confidence INTEGER, method TEXT, proto TEXT, owner TEXT, rpcnum TEXT, fingerprint TEXT)")
		puts "|#{rtv.length.to_s}|#{$!}|".red
	else
		puts "We shouldn't be here....ever.".blue.on_white.blink
		pp notable
	end
end

def create_os_table( db_file = @database )
	db = SQLite3::Database.new(db_file)
	notable = false
	r = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='os'")
	r.flatten!
	if r[0].nil? || r[0] == ""
		notable = true
	elsif r[0] == "os"
		puts "os table exists".blue
		return 0
	else
		puts "Unexpected result:".red
		pp r
		puts
		return -1
	end

	if (notable)
		print "Creating the os table...".yellow
		rtv = db.execute("CREATE TABLE os(hid INTEGER, name TEXT, family TEXT, generation TEXT, type TEXT, vendor TEXT, accuracy INTEGER)")
		puts "|#{rtv.length.to_s}|#{$!}|".red
	else
		puts "We shouldn't be here....ever.".blue.on_white.blink
		pp notable
	end
end

def create_database( _db_file = @database )
	create_nmap_table(_db_file)

	create_hosts_table(_db_file)

	create_seq_table(_db_file)

	create_ports_table(_db_file)

	create_os_table(_db_file)
end

def check_scan_record(_args, _starttime, _endtime)
	db = SQLite3::Database.new(@database)
	r = db.execute("SELECT sid FROM nmap WHERE args='#{_args}' AND starttime='#{_starttime}' AND endtime='#{_endtime}'")
	r.flatten!
	if r[0].nil? || r[0] == ""
		# no record exists
		return false
	else
		# a scan already exists,
		# so return the sid
		return r[0]
	end
end

def check_host_record(_ip4, _ip6, _mac, _hostname, *_sid)
	db = SQLite3::Database.new(@database)
	r = ''
	if _sid
		r = db.execute("SELECT hid FROM hosts WHERE ip4='#{_ip4}' AND ip6='#{_ip6}' AND mac='#{_mac}' AND hostname='#{_hostname}' AND sid='#{_sid}'")
		pp r
	else
		r = db.execute("SELECT hid FROM hosts WHERE ip4='#{_ip4}' AND ip6='#{_ip6}' AND mac='#{_mac}' AND hostname='#{_hostname}'")
	end 		# if _sid
	r.flatten!
	if r[0].nil? || r[0] == ""
		# no record exists
		return false
	else
		# a host already exists,
		# so return the hid
		return r[0]
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

create_database(@database)

db = SQLite3::Database.new(@database)

# start with the basics -- log it all
sid = check_scan_record(nmap.session.scan_args, nmap.session.start_time.to_s, nmap.session.stop_time.to_s)
#pp sid
if sid.is_a?(Integer) && sid > 0
	puts "Record already exists.  SID = '#{sid}'"
else
	sql1 = "INSERT INTO nmap (version, xmlversion, args, types, starttime, startstr, endtime, endstr, numservices) VALUES ('#{nmap.session.nmap_version}', '#{nmap.session.xml_version}', '#{nmap.session.scan_args}', '#{nmap.session.scan_types}', '#{nmap.session.start_time.to_s}', '#{nmap.session.start_str}', '#{nmap.session.stop_time.to_s}', '#{nmap.session.stop_str}', '#{nmap.session.numservices}')"
	puts "SQL1: #{sql1}".yellow
	rtv = db.execute(sql1)
	sid = check_scan_record(nmap.session.scan_args, nmap.session.start_time.to_s, nmap.session.stop_time.to_s)
end

if nmap.hosts.nil? || nmap.hosts.length == 0
	puts "There are no hosts in this scan."
else
	nmap.hosts do |host|
		hid = check_host_record(host.ip4_addr, host.ip6_addr, host.mac_addr, host.hostname)
		if hid.is_a?(Integer) && hid > 0
			r = db.execute("SELECT sid,hid FROM hosts WHERE sid='#{sid}' AND hid='#{hid}'")
			r.flatten!
			#pp r
			if r[0] == sid && r[1] == hid
				puts "Scan and host already exist.  Skipping."
				next
			else	# hid exists, but sid is different, so different hid (the way this db is structured).
				puts "Scan is different, so this is a new host."
				puts "Fall through to inserting new host data."
			
				sql2 = %{INSERT INTO hosts (sid, ip4, ip4num, hostname, status, tcpcount, 
					udpcount, mac, vendor, ip6, distance, uptime, upstr) VALUES ('#{sid}', 
					'#{host.ip4_addr}', '[ip4num]', '#{host.hostname}', '#{host.status}', 
					'#{host.getports(:tcp).length.to_s}', '#{host.getports(:udp).length.to_s}', 
					'#{host.mac_addr}', '#{host.mac_vendor}', '#{host.ip6_addr}', 
					'#{host.distance.to_s}', '#{host.uptime_seconds.to_s}', 
					'#{host.uptime_lastboot}')}.gsub(/(\t|\s)+/, " ").strip
				puts "SQL2: #{sql2}".red
				db.execute(sql2)
				puts "Host record inserted."
				hid = check_host_record(host.ip4_addr, host.ip6_addr, host.mac_addr, host.hostname, sid)
				if hid
					sql3 = %{INSERT INTO sequencing (hid, tcpclass, tcpindex, tcpvalues,
						ipclass, ipvalues, tcptclass, tcptvalues) VALUES ('#{hid}', 
						'#{host.tcpsequence_class}', '#{host.tcpsequence_index}', 
						'#{host.tcpsequence_values}', '#{host.ipidsequence_class}',
						'#{host.ipidsequence_values}', '#{host.tcptssequence_class}',
						'#{host.tcptssequence_values}')}.gsub(/(\t|\s)+/, " ").strip
					puts "SQL3: #{sql3}".cyan
					db.execute(sql3)
					puts "Sequencing record inserted."
			
					[:tcp, :udp].each do |type|
						host.getports(type) do |port|
							sql4 = %{INSERT INTO ports (hid, port, type, state, name, tunnel,
								product, version, extra, confidence, method, proto, owner, 
								rpcnum, fingerprint) VALUES ('#{hid}', '#{port.num}', '',
								'#{port.state}', '#{port.service.name}', '#{port.service.tunnel}',
								'#{port.service.product}', '#{port.service.version}', 
								'#{port.service.extra}', '#{port.service.confidence}',
								'#{port.service.method}', '#{port.service.proto}',
								'#{port.service.owner}', '#{port.service.rpcnum}',
								'#{port.service.fingerprint}')}.gsub(/(\t|\s)+/, " ").strip
							puts "#{sql4}".green
							db.execute(sql4)
							puts "Port record inserted."
						end		# host.getports()
					end		# port types

					sql5 = %{INSERT INTO os (hid, name, family, generation, type, vendor,
						accuracy) VALUES ('#{hid}', '#{host.os.name}', '#{host.os.osfamily}',
						'#{host.os.osgen}', '#{host.os.ostype}', '#{host.os.osvendor}',
						'#{host.os.class_accuracy}')}.gsub(/(\t|\s)+/, " ").strip
					puts "#{sql5}".magenta
					db.execute(sql5)
					puts "OS record inserted."
				else
					pp hid
					raise "Got a false value for hid after record entry."
				end		# if hid
			end		# if sid && hid
		else 
			raise "Unexpected result after host: HID='#{hid}'"
		end		# if hid == false
	end		# nmap.hosts loop
end		# if nmap.hosts.nil?


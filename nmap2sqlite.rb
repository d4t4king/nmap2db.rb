#!/usr/bin/env ruby

###############################################################################
#
#	Script:			nmap2sqlite.rb
#
#	Author:			Charlie Heselton aka dataking <dataking [at] gmail [dot] com
#
#	Date:			9/24/2015
#
#	Version:		0.1
#
#	Description:	This script will take an XML file from nmap output, and
#		enter it into the (default) database.
#
#	TODO:
#		* Expand verbose/quiet to "degrees of verbosity/silence?
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
	['--verbose', '-v', GetoptLong::NO_ARGUMENT ],
	['--quiet', '-q', GetoptLong::NO_ARGUMENT ],
	['--help', '-h', GetoptLong::NO_ARGUMENT ],
)

def usage(noexit=false) 
	puts <<-EOS

#{$0} [-i|--input] <input file> [-d|--database] <path/to/database/file> [-h|--help] [-v|--verbose] [-q|--quiet]

-i|--input			Specifies the full path to the nmap XML input file.
-d|--database			Specifies the full path to the database to be created/updated.
-h|--help			Displays this helpful message, and exits.
-v|--verbose			Displays more output than normal.
-q|--quiet			Displays less output than normal.


EOS
	unless noexit
		exit 1
	end
end

input = ''; @verbose = false; @quiet = false
@database = 'nmap_scans.db'
opts.each do |opt,arg|
	case opt
	when '--input'
		input = arg
	when '--database'
		@database = arg
	when '--verbose'
		@verbose = true
	when '--quiet'
		@quiet = true
	when '--help'
		usage()
	end
end

if @verbose && @quiet
	raise "Can't be verbose and quiet at the same time.  Pick one."
end

if @verbose
	puts <<-EOS

################
# Input file:		#{input}
# Database file:	#{@database}
################

EOS

end

def create_nmap_table( db_file = @database )
	db = SQLite3::Database.new(db_file)
	notable = false
	r = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nmap'")
	r.flatten!
	if r[0].nil?
		notable = true
	elsif r[0] == "nmap"
		puts "nmap table exists".blue if @verbose
		return 0
	else
		puts "Unexpected result:".red
		pp r
		puts
		return -1
	end

	if notable
		print "Creating the nmap table....".yellow if @verbose
		rtv = db.execute("CREATE TABLE nmap (sid INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, xmlversion TEXT, args TEXT, types TEXT, starttime INTEGER, startstr TEXT, endtime INTEGER, endstr TEXT, numservices INTEGER)")
		puts "|#{rtv.length}|#{$!}|".red if @verbose
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
	if r[0].nil?
		notable = true
	elsif r[0] == "hosts"
		puts "hosts table exists".blue if @verbose
		return 0
	else
		puts "Unexpected result:".red
		pp r
		puts
		return -1
	end

	if notable
		print "Creating the hosts table...".yellow if @verbose
		rtv = db.execute("CREATE TABLE hosts (sid INTEGER, hid INTEGER PRIMARY KEY AUTOINCREMENT, ip4 TEXT, ip4num TEXT, hostname TEXT, status TEXT, tcpcount INTEGER, udpcount INTEGER, mac TEXT, vendor TEXT, ip6 TEXT, distance INTEGER, uptime TEXT, upstr TEXT)")
		puts "|#{rtv.length}|#{$!}|".red if @verbose
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
	if r[0].nil?
		notable = true
	elsif r[0] == "sequencing"
		puts "sequencing table exists".blue if @verbose
		return 0
	else
		puts "Unexpected result:".red
		pp r
		puts
		return -1
	end

	if notable
		print "Creating the sequencing table...".yellow if @verbose
		rtv = db.execute("CREATE TABLE sequencing (hid INTEGER, tcpclass TEXT, tcpindex TEXT, tcpvalues TEXT, ipclass TEXT, ipvalues TEXT, tcptclass TEXT, tcptvalues TEXT)")
		puts "|#{rtv.length}|#{$!}|".red if @verbose
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
	if r[0].nil?
		notable = true
	elsif r[0] == "ports"
		puts "ports table exists".blue if @verbose
		return 0
	else
		puts "Unexpected result:".red
		pp r
		puts
		return -1
	end

	if notable
		print "Creating the ports table...".yellow if @verbose
		rtv = db.execute("CREATE TABLE ports (hid INTEGER, port INTEGER, type TEXT, state TEXT, name TEXT, tunnel TEXT, product TEXT, version TEXT, extra TEXT, confidence INTEGER, method TEXT, proto TEXT, owner TEXT, rpcnum TEXT, fingerprint TEXT)")
		puts "|#{rtv.length}|#{$!}|".red if @verbose
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
	if r[0].nil?
		notable = true
	elsif r[0] == "os"
		puts "os table exists".blue if @verbose
		return 0
	else
		puts "Unexpected result:".red
		pp r
		puts
		return -1
	end

	if (notable)
		print "Creating the os table...".yellow if @verbose
		rtv = db.execute("CREATE TABLE os(hid INTEGER, name TEXT, family TEXT, generation TEXT, type TEXT, vendor TEXT, accuracy INTEGER)")
		puts "|#{rtv.length}|#{$!}|".red if @verbose
	else
		puts "We shouldn't be here....ever.".blue.on_white.blink
		pp notable
	end
end

def create_database( i_db_file = @database )
	create_nmap_table(i_db_file)

	create_hosts_table(i_db_file)

	create_seq_table(i_db_file)

	create_ports_table(i_db_file)

	create_os_table(i_db_file)
end

def check_scan_record(args, starttime, endtime)
	db = SQLite3::Database.new(@database)
	r = db.execute("SELECT sid FROM nmap WHERE args='#{args}' AND starttime='#{starttime}' AND endtime='#{endtime}'")
	r.flatten!
	if r[0].nil?
		# no record exists
		return false
	else
		# a scan already exists,
		# so return the sid
		return r[0]
	end
end

nmap = Nmap::Parser.new
if File.exist?(input) && !File.directory?(input) && !File.zero?(input)
	nmap.parsefile(input)
else
	usage(true)
	if !File.exist?(input)
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
if sid.is_a?(Integer) && sid > 0
	puts "Scan record already exists.  SID = '#{sid}'" unless @quiet
else
	sql1 = "INSERT INTO nmap (version, xmlversion, args, types, starttime, startstr, endtime, endstr, numservices) VALUES ('#{nmap.session.nmap_version}', '#{nmap.session.xml_version}', '#{nmap.session.scan_args}', '#{nmap.session.scan_types}', '#{nmap.session.start_time}', '#{nmap.session.start_str}', '#{nmap.session.stop_time}', '#{nmap.session.stop_str}', '#{nmap.session.numservices}')"
	puts "SQL1: #{sql1}".yellow if @verbose
	#rtv = db.execute(sql1)			# uncomment this if you want to use rtv somewhere.
	sid = check_scan_record(nmap.session.scan_args, nmap.session.start_time.to_s, nmap.session.stop_time.to_s)
end

if nmap.hosts.nil? || nmap.hosts.length == 0
	puts "There are no hosts in this scan." unless @quiet
else
	nmap.hosts do |host|
		hid = db.execute("SELECT hid FROM hosts where ip4='#{host.ip4_addr}'")
		if hid.is_a?(Array)
			if hid[0].is_a?(Array)
				hid.flatten!
				# apparently it is bad style to have deeply nested blocks (4+ levels)
				# let's see if this breaks anything
				#if hid.length > 1
				#	puts "(1) Got more than one value for hid lookup.  Truncate DB." unless @quiet
				#else
					hid = hid[0]
				#end
			end
		end
		if hid.is_a?(Integer) && hid > 0
			s = db.execute("SELECT sid,hid FROM hosts WHERE sid='#{sid}' AND hid='#{hid}'")
			s.flatten!
			if s[0] == sid && s[1] == hid
				puts "Scan and host already exist.  Skipping." unless @quiet
				next
			end		# if sid && hid
			# hid exists, but sid is different, so different hid (the way this db is structured).
		end		# if hid(int)

		sql2 = %{INSERT INTO hosts (sid, ip4, ip4num, hostname, status, tcpcount, 
			udpcount, mac, vendor, ip6, distance, uptime, upstr) VALUES ('#{sid}', 
			'#{host.ip4_addr}', '[ip4num]', '#{host.hostname}', '#{host.status}', 
			'#{host.getports(:tcp).length}', '#{host.getports(:udp).length}', 
			'#{host.mac_addr}', '#{host.mac_vendor}', '#{host.ip6_addr}', 
			'#{host.distance}', '#{host.uptime_seconds}', 
			'#{host.uptime_lastboot}')}.gsub(/(\t|\s)+/, " ").strip
		puts "SQL2: #{sql2}".green if @verbose
		db.execute(sql2)
		puts "Host record inserted." unless @quiet
		hid = db.execute("SELECT hid FROM hosts where ip4='#{host.ip4_addr}' AND sid='#{sid}'")
		if hid.is_a?(Array)
			if hid[0].is_a?(Array)
				hid.flatten!
				# apparently it is bad style to have deeply nested blocks (4+ levels)
				# let's see if this breaks anything
				#if hid.length > 1
				#	puts "(2) Got more than one value for hid lookup.  Truncate DB." unless @quiet
				#else
					hid = hid[0]
				#end
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
		end		# if hid
	end		# nmap.hosts loop
end		# if nmap.hosts.nil?


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
database = 'nmap_scans.db'
opts.each do |opt,arg|
	case opt
	when '--input'
		input = arg
	when '--database'
		database = arg
	end
end

nmap = Nmap::Parser.new
begin
	if File.exists?(input) && !File.directory?(input) && !File.zero?(input)
		nmap.parsefile(input)
	else
		if !File.exists?(input)
			raise "Input file (#{input}) doesn't appear to exist.  Nothing to do."
		elsif File.directory?(input)
			raise "Input file (#{input}) appears to be a directory.  I don't know how to handle those (yet)."
		elsif File.zero?(input)
			raise "Input file (#{input}) appears to be zero (0) bytes.  Nothing to do."
		else
			raise "Unhandled error for input file (#{input})."
		end
	end
rescue StandardError => se
	raise se
end

db = SQLite3::Database.new(database)

# start with the basics -- log it all
sql1 = "INSERT INTO nmap (version, xmlversion, args, types, starttime, startstr, endtime, endstr, numservices) VALUES ('#{nmap.session.nmap_version}', '#{nmap.session.xml_version}', '#{nmap.session.scan_args}', '#{nmap.session.scan_types}', '#{nmap.session.start_time.to_s}', '#{nmap.session.start_str}', '#{nmap.session.stop_time.to_s}', '#{nmap.session.stop_str}', '#{nmap.session.numservices}')"

puts "SQL1: #{sql1}".yellow

db.execute(sql1)

puts "Scan record inserted."

sid = ''
db.execute("SELECT sid FROM nmap WHERE args='#{nmap.session.scan_args}' and starttime='#{nmap.session.start_time}' and endtime='#{nmap.session.stop_time}'") do |r|
	if r.is_a?(Array)
		sid = r[0]
	else				# if it's not an array, assume it's a string
		r.chomp!
		sid = r
	end
end

nmap.hosts do |host|
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

	hid = ''
	db.execute("SELECT hid FROM hosts WHERE ip4='#{host.ip4_addr}' and status='#{host.status}' and tcpcount='#{host.getports(:tcp).length.to_s}'") do |r|
		if r.is_a?(Array)
			hid = r[0]
		else			# if it's not an array, assume it's a string
			r.chomp!
			hid = r
		end
	end

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
		end
	end

	sql5 = %{INSERT INTO os (hid, name, family, generation, type, vendor,
		accuracy) VALUES ('#{hid}', '#{host.os.name}', '#{host.os.osfamily}',
		'#{host.os.osgen}', '#{host.os.ostype}', '#{host.os.osvendor}',
		'#{host.os.class_accuracy}')}.gsub(/(\t|\s)+/, " ").strip

	puts "#{sql5}".magenta

	db.execute(sql5)

	puts "OS record inserted."
end


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
#
###############################################################################

require 'rubygems'
require 'colorize'
require 'pp'
require 'nmap/parser'
require 'getoptlong'

opts = GetoptLong.new(
	['--input', '-i', GetoptLong::REQUIRED_ARGUMENT],
)

input = ''
opts.each do |opt,arg|
	case opt
	when '--input'
		input = arg
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

# start with the basics -- log it all
sql1 = "INSERT INTO nmap (version, xmlversion, args, types, starttime, startstr, endtime, endstr, numservices) VALUES ('#{nmap.session.nmap_version}', '#{nmap.session.xml_version}', '#{nmap.session.scan_args}', '#{nmap.session.scan_types}', '#{nmap.session.start_time.to_s}', '#{nmap.session.start_str}', '#{nmap.session.stop_time.to_s}', '#{nmap.session.stop_str}', '#{nmap.session.numservices}')"

puts "SQL1: #{sql1}".yellow

nmap.hosts do |host|
	sql2 = %{INSERT INTO hosts (sid, ip4, ip4num, hostname, status, tcpcount, 
		udpcount, mac, vendor, ip6, distance, uptime, upstr) VALUES ('[sid]', 
		'#{host.ip4_addr}', '[ip4num]', '#{host.hostname}', '#{host.status}', 
		'#{host.getports(:tcp).length.to_s}', '#{host.getports(:udp).length.to_s}', 
		'#{host.mac_addr}', '#{host.mac_vendor}', '#{host.ip6_addr}', 
		'#{host.distance.to_s}', '#{host.uptime_seconds.to_s}', 
		'#{host.uptime_lastboot}')}.gsub(/(\t|\s)+/, " ").strip

	puts "SQL2: #{sql2}".red

	sql3 = %{INSERT INTO sequencing (hid, tcpclass, tcpindex, tcpvalues,
		ipclass, ipvalues, tcptclass, tcptvalues) VALUES ('[hid]', 
		'#{host.tcpsequence_class}', '#{host.tcpsequence_index}', 
		'#{host.tcpsequence_values}', '#{host.ipidsequence_class}',
		'#{host.ipidsequence_values}, '#{host.tcptssequence_class}',
		'#{host.tcptssequence_values}')}.gsub(/(\t|\s)+/, " ").strip

	puts "SQL3: #{sql3}".cyan
end


#!/usr/bin/env ruby

###############################################################################
#
#	Script:			nmap2csv.rb
#
#	Author:			Charlie Heselton (cheselton@semprautilities.com)
#
#	Date:			5/10/2016
#
#	Version:		0.1
#
#	Description:	This script will take an XML file from nmap output, and
#		output a CSV file, or alternatively a more advanced Excel spreadsheet/
#		database.
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
require 'writeexcel'
require 'csv'

opts = GetoptLong.new(
	['--input', '-i', GetoptLong::REQUIRED_ARGUMENT ],
	['--output', '-o', GetoptLong::REQUIRED_ARGUMENT ],
	['--verbose', '-v', GetoptLong::NO_ARGUMENT ],
	['--quiet', '-q', GetoptLong::NO_ARGUMENT ],
	['--help', '-h', GetoptLong::NO_ARGUMENT ],
	['--excel', '-E', GetoptLong::NO_ARGUMENT ],
	['--up', '-U', GetoptLong::NO_ARGUMENT ],
)

def usage(noexit=false) 
	puts <<-EOS

#{$0} [-i|--input] <input file> [-o|--output] <path/to/csv/file> [-h|--help] [-v|--verbose] [-q|--quiet]

-i|--input			Specifies the full path to the nmap XML input file.
-0|--output			Specifies the full path to the csv to be created.
-h|--help			Displays this helpful message, and exits.
-v|--verbose			Displays more output than normal.
-q|--quiet			Displays less output than normal.
-E|--excel			Writes the output to am Excel spreadsheet/workbook, rather than the
					simpler CSV format.
-U|--up				Only print/write data for hosts that are "up".


EOS
	unless noexit
		exit 1
	end
end

input = ''; status = ''
@verbose = false; @quiet = false
help = false; excel = false; output = ''
opts.each do |opt,arg|
	case opt
	when '--input'
		input = arg
	when '--output'
		output = arg
	when '--verbose'
		@verbose = true
	when '--quiet'
		@quiet = true
	when '--excel'
		excel = true
	when '--up'
		status = "up"
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

if nmap.hosts.nil? || nmap.hosts.length == 0
	puts "There are no hosts in this scan." unless @quiet
else
	if excel
		# write the Excel spreadsheet
		workbook = WriteExcel.new(output)
		ws_summary = workbook.add_worksheet('Summary')
		summary_header_row = Array.new
		summary_header_row = ['IP','Hostname','OS Guess','Accuracy','Host Status','Open Ports','Start Time','End Time','Duration','MAC Address','MAC Vendor','Scripts']
		ws_summary.write_row('A1',summary_header_row)
		ws_ports = workbook.add_worksheet('Ports')
		ports_header_row = Array.new
		ports_header_row = [ 'IP','Port Number','Protocol','Service','State','Reason','Scripts' ]
		ws_ports.write_row('A1',ports_header_row)
		i = 2; j = 2
		nmap.hosts(status) do |host|
			host_data_row = [ host.ipv4_addr.to_s, host.hostname.to_s, host.os.name.to_s, host.status.to_s, host.getportlist([:tcp,:udp], "open").to_s, host.starttime.to_s, host.endtime.to_s, (host.endtime.to_i - host.starttime.to_i).to_s, host.mac_addr.to_s, host.mac_vendor.to_s ]
			puts host_data_row.to_s if @verbose
			ws_summary.write("A#{i}",host_data_row)
			#ws_summary.write("A#{i}",host.ipv4_addr.to_s)
			#ws_summary.write("B#{i}",host.hostname.to_s)
			#ws_summary.write("C#{i}",host.os.name.to_s)
			#ws_summary.write("D#{i}",host.os.class_accuracy.to_s)
			#ws_summary.write("E#{i}",host.status.to_s)
			#ws_summary.write("F#{i}",host.getportlist([:tcp,:udp],"open").to_s)
			#ws_summary.write("G#{i}",host.starttime.to_s)
			#ws_summary.write("H#{i}",host.endtime.to_s)
			#ws_summary.write("I#{i}","=H#{i}-G#{i}")
			#ws_summary.write("J#{i}",host.mac_addr.to_s)
			#ws_summary.write("K#{i}",host.mac_vendor.to_s)
			host.getports([:tcp,:udp],"open") do |port|
				ws_ports.write("A#{j}",host.ipv4_addr.to_s)
				ws_ports.write("B#{j}",port.num.to_s)
				ws_ports.write("C#{j}",port.proto.to_s.upcase)
				ws_ports.write("D#{j}","#{port.service.name}:#{port.service.product}:#{port.service.version}".to_s)
				#ws_ports.write("D#{j}",port.service.inspect.to_s)
				ws_ports.write("E#{j}",port.state.to_s)
				ws_ports.write("F#{j}",port.reason.to_s.upcase)
				ws_ports.write("G#{j}",port.scripts.to_s)
				j += 1
			end
			i += 1
		end
		workbook.close
	else
		# write to CSV
		CSV.open(output, "wb") do |csv|
			summary_header_row = Array.new
			summary_header_row = ['IP','Hostname','OS Guess','Accuracy','Host Status','Open Ports','Start Time','End Time','Duration','MAC Address','MAC Vendor','Scripts']
			csv << summary_header_row
			nmap.hosts(status) do |host|
				host_data_row = [ host.ipv4_addr.to_s, host.hostname.to_s, host.os.name.to_s, host.status.to_s, host.getportlist([:tcp,:udp], "open").to_s, host.starttime.to_s, host.endtime.to_s, (host.endtime.to_i - host.starttime.to_i).to_s, host.mac_addr.to_s, host.mac_vendor.to_s ]
				csv << host_data_row
				puts host_data_row.to_s if @verbose
			end
		end
	end
end	

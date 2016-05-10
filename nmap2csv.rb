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
	['--output', '-o', GetoptLong::REQUIRED_ARGUMENT ],
	['--verbose', '-v', GetoptLong::NO_ARGUMENT ],
	['--quiet', '-q', GetoptLong::NO_ARGUMENT ],
	['--help', '-h', GetoptLong::NO_ARGUMENT ],
)

def usage(noexit=false) 
	puts <<-EOS

#{$0} [-i|--input] <input file> [-o|--output] <path/to/csv/file> [-h|--help] [-v|--verbose] [-q|--quiet]

-i|--input			Specifies the full path to the nmap XML input file.
-0|--output			Specifies the full path to the csv to be created.
-h|--help			Displays this helpful message, and exits.
-v|--verbose			Displays more output than normal.
-q|--quiet			Displays less output than normal.


EOS
	unless noexit
		exit 1
	end
end

input = ''; @verbose = false; @quiet = false
help = false; output = ''
opts.each do |opt,arg|
	case opt
	when '--input'
		input = arg
	when '--output'
		@output = arg
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
	if nmap.hosts.length > 0
		puts "Found the following hosts in the input file: ".green
		nmap.hosts do |host|
			puts "Hostname: #{host.hostname.to_s} IP: #{host.ipv4_addr.to_s}"
		end
	end
end		# if nmap.hosts.nil?


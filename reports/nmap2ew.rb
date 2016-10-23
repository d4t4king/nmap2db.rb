#!/usr/bin/env ruby

require 'rubygems'
require 'colorize'
require 'pp'
require 'nmap/parser'
require 'sqlite3'
require 'getoptlong'

def show_help()

	print <<-EOS

#{$0} [-h|--help] [-i|--input] <input_file> [-d|--database] </path/to/database/file> [-b|--binary[

-h|--help			Display this useful help message
-i|--input			Parse the supplied input file for hosts/URLs.  
-d|--database			Query targets from the specified sqlite/nmap database.  Expects the schema
				defined in other scripts in this repo.
-b|--binary			Path to the eyewitness script/binary, in case not in expected location.
				Expected location is in /usr/bin/(eyewitness).  *The file is not actually likelt
				to be a binary, but a Python script.  It doesn't really matter, so long 
				as the python script acts like a binary.

EOS

	exit 1

end
	
ew_cmd = '/usr/bin/eyewitness '

opts = GetoptLong.new(
	[ '--input', '-i', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--database', '-d', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--help', '-h', GetoptLong::NO_ARGUMENT ],
	[ '--web', GetoptLong::NO_ARGUMENT ],
	[ '--s-web', GetoptLong::NO_ARGUMENT ],
)

input = ''
database = ''
bin = ''
web = false
s_web = false

opts.each do |opt,arg|
	case opt
	when '--help'
		show_help
	when '--input'
		input = arg
	when '--database'
		database = arg
	when '--binary'
		bin = arg
	when '--web'
		web = true
	when '--s-web'
		s_web = true
	else
		show_help
	end
end

if bin && (!bin.nil? && bin != "")
	ew_cmd = bin
end

unless web || s_web
	$stderr.puts "Assuming you want (at least) HTTP, since you didn't specify.".yellow 
	web = true
end

parser = Nmap::Parser.new

unless input.nil? || input == ''
	if File.exist?(input) && !File.directory?(input) && !File.zero?(input)
		parser.parsefile(input)
	else
		if File.directory(input)
			raise "File (#{input}) appears to be a directory."
		elsif File.zero?(input)
			raise "Input file (#{input}) appears to be zero (0) bytes."
		end
	end

	parser.hosts("up").each do |h|
		#print "#{h.ip4_addr}:  ".magenta
		#pp h
		if web
			puts "http://#{h.ip4_addr}/" unless h.getport(:tcp, '80').nil?
		end
		if s_web
			puts "https://#{h.ip4_addr}/" unless h.getport(:tcp, '443').nil?
		end
	end
end

### ...why'd you have to go and let this die..."


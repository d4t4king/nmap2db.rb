#!/usr/bin/env ruby

require 'rubygems'
require 'colorize'
require 'pp'
require 'nmap/parser'
require 'sqlite3'
require 'getoptlong'

def show_help(_quit, *_uo, *_uoo)

	if _uo && (_uoo.nil? || _uoo == "")
		raise "Program error.  Option expected when unexpected option found."
	end

	print <<-EOS

#{$0} [-h|--help] [-i|--input] <input_file> [-d|--database] </path/to/database/file>

-h|--help			Display this useful help message
-i|--input			Parse the supplied input file for hosts/URLs.  
-d|--database		Query targets from the specified sqlite/nmap database.  Expects the schema
					defined in other scripts in this repo.
-b|--binary			Path to the eyewitness script/binary, in case not in expected location.
					Expected location is in /usr/bin/(eyewitness)
EOS

	if _uo && (!_uoo.nil? && _uoo != "")
		raise "Unrecognized option: #{_uoo}"
	elsif _quit
		exit 1
	else
		puts "...end help..."
	end

end
	
ew_bin = '/usr/bin/eyewitness '

if bin && (!bin.nil? && bin != "")
	ew_cmd = bin
end

pts = GetoptsLong.new(
	[ '--input', '-i', GetoptsLong::REQUIRED_ARGUMENT ],
	[ '--database', '-d', GetoptsLong::REQUIRED_ARGUMENT ],
	[ '--help', '-h', GetoptLong::NO_ARGUMENT ],
)

opts.each do |opt,arg|
	case opt
	when '--help'
		show_help(false)
	when '--input'
		input = arg
	when '--database'
		database = arg
	else
		show_help(true, true, opt)
	end
end

parser = Nmap::Parser.new

unless input.nil? || input == ''
	if File.exists?(input) && !File.directory?(input) && !File.zero?(input)
		parser.parsefile(input)
	end

	parser.hosts.each do |h|
		if h.getports(:tcpi, 'open').include?('80')
			puts "#{h.ip4_addr},#{h.getport(:tcp, '80')}".green
		end
	end
end

### ...why'd you have to go and let this die..."


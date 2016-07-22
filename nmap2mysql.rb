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
-d|--database			Specifies the name of the mysql database.  Creates it, if it does not exist.
-H|--host				Specifies the name of the mysql host.
-u|--user				Specifies the name of the user for the mysql database.
-p|--pass				Specifies the password for the user specified with '-u'
-h|--help				Displays this helpful message, and exits.
-v|--verbose			Displays more output than normal.
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



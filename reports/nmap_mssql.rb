#!/usr/bin/env ruby

require 'colorize'
require 'pp'
require 'nmap/parser'

if ARGV[0].size == 0
	raise "Need an input file on the command line.".red
else 
	nmap = Nmap::Parser.parsefile(ARGV[0])
	nmap.hosts("up") do |host|
		puts "#{host.addr} is up:"
		pp host
		exit 0
	end
end


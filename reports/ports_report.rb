#!/usr/bin/env ruby

require 'rubygems'
require 'colorize'
require 'sqlite3'
require 'getoptlong'

opts = GetoptLong.new(
	['--database', '-d', GetoptLong::OPTIONAL_ARGUMENT ],
)

database = ''



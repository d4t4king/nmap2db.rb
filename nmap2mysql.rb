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

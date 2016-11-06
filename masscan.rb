require 'pp'
require 'rexml/document'
require 'date'

module Masscan
	# Holder for all the subclasses to come
end

class Masscan::ScanInfo
	# scanner name
	attr_accessor :scanner
	# the time the scan started
	attr_accessor :start_time
	# scanner version
	attr_accessor :scanner_version
	# xml output version
	attr_accessor :xml_version
	# scan type
	# This is more relevant for nmap scans.  Masscan ONLY
	# does SYN scans.
	attr_accessor :scan_type
	# scan protocol used for this scan
	attr_accessor :scan_protocol
	# time the scan ended
	attr_accessor :stop_time
	# date string scan ended
	attr_accessor :stop_str
	# total time in seconds
	attr_accessor :elapsed
	# hosts up
	attr_accessor :hosts_up
	# hosts down -- this might always be 0 for masscan
	attr_accessor :hosts_down
	# total hosts found
	attr_accessor :total_hosts
	# array of all discovered host objects
	attr_accessor :hosts

	def initialize(obj)
		@hosts = Array.new unless hosts.is_a?(Array)
		host_idx = Array.new
		host_port_idx = Hash.new
		if obj.is_a?(REXML::Document)
			nmaprun = obj.elements["nmaprun"]
			@scanner = nmaprun.attributes["scanner"]
			@start_time = DateTime.strptime(nmaprun.attributes["start"].to_s, '%s')
			@scanner_version = nmaprun.attributes["version"]
			@xml_version = nmaprun.attributes["xmloutputversion"]
			scaninfo = obj.elements["nmaprun"].elements["scaninfo"]
			@scan_type = scaninfo.attributes["type"]
			@scan_protocol = scaninfo.attributes["protocol"]
			runstats = obj.elements["nmaprun"].elements["runstats"]
			finished = runstats.elements["finished"]
			hosts = runstats.elements["hosts"]
			@stop_time = DateTime.strptime(finished.attributes["time"], "%s")
			@stop_str = finished.attributes["timestr"]
			@elapsed = finished.attributes["elapsed"]
			@hosts_up = hosts.attributes["up"].to_i
			@hosts_down = hosts.attributes["down"].to_i
			@total_hosts = hosts.attributes["total"].to_i
			
		else
			raise "Unrecognized object type: #{obj.class}"
		end
	end

	alias new initialize
end

class Masscan::Host
	# Status of the host, typically "up" or "down"
	attr_accessor :status
	# IPv4 address
	attr_accessor :ip4_addr
	# host stop time
	attr_accessor :stop_time
	# ports
	attr_accessor :ports

	alias ipv4_addr ip4_addr

	# Returns the IPv4 address of the host
	def addr
		@ip4_addr
	end

	def addport(obj)
	end

	def initialize(obj)
		if obj.is_a?(REXML::Element)
			address = obj.elements["address"]
			addrtype = address.attributes['addrtype']
			case addrtype
			when "ipv4"
				@ip4_addr = obj.elements["address"].attributes["addr"]
			end
			@stop_time = DateTime.strptime(obj.attributes["endtime"].to_s, '%s')
			# masscan only records one port per host record, 
			# but @ports should be an array
			@ports = Array.new unless @ports.is_a?(Array)
			p = Masscan::Host::Port.new(obj.elements["ports"])
			@ports.push(p)
		end
	end

	alias new initialize
end

class Masscan::Host::Port
	# port number
	attr_accessor :port_id
	# protocol
	attr_accessor :protocol
	# port state
	attr_accessor :state
	# reason for state
	attr_accessor :reasn
	# reason ttl
	attr_accessor :reason_ttl

	def initialize(obj)
		if obj.is_a?(REXML::Element)
			@port_id = obj.elements["port"].attributes["portid"].to_i
			@protocol = obj.elements["port"].attributes["protocol"]
			@state = obj.elements["port"].elements["state"].attributes["state"]
			@reason = obj.elements["port"].elements["state"].attributes["reason"]
			@reason_ttl = obj.elements["port"].elements["state"].attributes["reason_ttl"].to_i
		end
	end

	alias new initialize
end

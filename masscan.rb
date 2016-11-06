require 'rexml/document'

module Masscan
	# Holder for all the subclasses to come
end

class Masscan::Host
	# Status of the host, typically "up" or "down"
	attr_accessor :status
	# IPv4 address
	attr_accessor :ip4_addr
	# stop time
	attr_accessor :stop_time

	alias ipv4_addr ip4_addr

	# Returns the IPv4 address of the host
	def addr
		@ip4_addr
	end

	def initialize(obj)
		if obj.is_a?(REXML::Element)
			addrtype = obj.elements["address"].attributes["addrtype"]
			case addrtype
			when "ipv4"
				@ip4_addr = obj.elements["address"].attributes["addr"]
			end
			@stop_time = obj.attributes["endtime"]
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
			@state = obj.elements["state"].attributes["state"]
		end
	end
end

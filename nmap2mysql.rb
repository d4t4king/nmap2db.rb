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
require 'date'

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
-d|--database				Specifies the name of the mysql database.  Creates it, if it does not exist.
-H|--host				Specifies the name of the mysql host.
-u|--user				Specifies the name of the user for the mysql database.
-p|--pass				Specifies the password for the user specified with '-u'
-h|--help				Displays this helpful message, and exits.
-v|--verbose				Displays more output than normal.
-q|--quiet				Displays less output than normal (or none at all).

END

	unless noexit
		exit 1
	end
end

input = ''; @verbose = false; @quiet = false
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
		@verbose = true
	when '--quiet'
		@quiet = true
	when '--help'
		usage()
	end
end

if @verbose && @quiet
	raise "Can't be verbose and quiest at the same time.  Pick one."
end


def create_nmap_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
	print "Creating the nmap table....".yellow if @verbose
	rtv = dbh.do("CREATE TABLE IF NOT EXISTS nmap (sid INT NOT NULL AUTO_INCREMENT, version VARCHAR(8), xmlversion VARCHAR(8), args VARCHAR(255), types VARCHAR(255), starttime DATETIME, startstr VARCHAR(255), endtime DATETIME, endstr VARCHAR(255), numservices INT, PRIMARY KEY (sid))")
	puts "|#{rtv}|#{$!}|".red if @verbose
	dbh.disconnect
	return rtv
end

def insert_nmap_record(p)
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	starttime = DateTime.strptime(starttime.to_s, "%s") if starttime.to_s =~ /^\d+$/
	endtime = DateTime.strptime(endtime.to_s, "%s") if endtime.to_s =~ /^\d+/
	# not sure why the starttime and endtime have the symbol reference.  code climate doesn't like it.
	#rtv = dbh.do("INSERT INTO nmap (version,xmlversion,args,types,starttime,startstr,endtime,endstr,numservices) VALUES ('#{version}','#{xmlversion}','#{args}','#{types}','#{starttime{:db}}','#{startstr}','#{endtime{:db}}','#{endstr}','#{numservices}')")
	rtv = dbh.do("INSERT INTO nmap (version,xmlversion,args,types,starttime,startstr,endtime,endstr,numservices) VALUES ('#{p[:version]}','#{p[:xmlversion]}','#{p[:args]}','#{p[:types]}','#{p[:starttime]}','#{p[:startstr]}','#{p[:endtime]}','#{p[:endstr]}','#{p[:numservices]}')")
	dbh.disconnect
	return rtv
end

def create_hosts_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
	print "Creating the host table....".yellow if @verbose
	rtv = dbh.do("CREATE TABLE IF NOT EXISTS hosts (sid INT NOT NULL, hid INT NOT NULL AUTO_INCREMENT, ip4 VARCHAR(16), ip4num VARCHAR(255), hostname VARCHAR(255), status VARCHAR(255), tcpcount INT, udpcount INT, mac VARCHAR(24), vendor VARCHAR(255), ip6 VARCHAR(64), distance INT, uptime VARCHAR(255), upstr VARCHAR(255), PRIMARY KEY(hid))")
	puts "|#{rtv}|#{$!}|".red if @verbose
	dbh.disconnect
	return rtv
end

def insert_host_record(sid,ip4,ip4num,hostname,status,tcpcount,udpcount,mac,vendor,ip6,distance,uptime,upstr)
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	rtv = dbh.do("INSERT INTO hosts (sid,ip4,ip4num,hostname,status,tcpcount,udpcount,mac,vendor,ip6,distance,uptime,upstr) VALUES ('#{sid}','#{ip4}','#{ip4num}','#{hostname}','#{status}','#{tcpcount}','#{udpcount}','#{mac}','#{vendor}','#{ip6}','#{distance}','#{uptime}','#{upstr}')")
	dbh.disconnect
	return rtv
end

def create_seq_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
	print "Creating the sequencing table....".yellow if @verbose
	rtv = dbh.do("CREATE TABLE IF NOT EXISTS sequencing (hid INT NOT NULL, sid INT NOT NULL, tcpclass VARCHAR(255), tcpindex VARCHAR(255), tcpvalues VARCHAR(255), ipclass VARCHAR(255), ipvalues VARCHAR(255), tcptclass VARCHAR(255), tcptvalues VARCHAR(255))")
	puts "|#{rtv}|#{$!}|".red if @verbose
	dbh.disconnect
	return rtv
end

def insert_seq_record(hid,sid,tcpclass,tcpindex,tcpvalues,ipclass,ipvalues,tcptclass,tcptvalues)
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	rtv = dbh.do("INSERT INTO sequencing (hid,sid,tcpclass,tcpindex,tcpvalues,ipclass,ipvalues,tcptclass,tcptvalues) VALUES ('#{hid}','#{sid}','#{tcpclass}','#{tcpindex}','#{tcpvalues}','#{ipclass}','#{ipvalues}','#{tcptclass}','#{tcptvalues}')")
	dbh.disconnect
	return rtv
end

def create_ports_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
	print "Creating the ports table....".yellow if @verbose
	rtv = dbh.do("CREATE TABLE IF NOT EXISTS ports (hid INT NOT NULL, sid INT NOT NULL, port INT, type VARCHAR(255), state VARCHAR(255), name VARCHAR(255), tunnel VARCHAR(255), product VARCHAR(255), version VARCHAR(255), extra VARCHAR(255), confidence INT, method VARCHAR(255), proto VARCHAR(255), owner VARCHAR(255), rpcnum VARCHAR(255), fingerprint TEXT)")
	puts "|#{rtv}|#{$!}|".red if @verbose
	dbh.disconnect
	return rtv
end

def insert_ports_record(hid,sid,port,type,state,name,tunnel,product,version,extra,confidence,method,proto,owner,rpcnum,fingerprint)
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	rtv = dbh.do("INSERT INTO ports (hid,sid,port,type,state,name,tunnel,product,version,extra,confidence,method,proto,owner,rpcnum,fingerprint) VALUES ('#{hid}','#{sid}','#{port}','#{type}','#{state}','#{name}','#{tunnel}','#{product}','#{version}','#{extra}','#{confidence}','#{method}','#{proto}','#{owner}','#{rpcnum}','#{fingerprint}')")
	dbh.disconnect
	return rtv
end

def create_os_table(db=@database,host=@host,username=@user,passwd=@pass)
	dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
	print "Creating the os table....".yellow if @verbose
	rtv = dbh.do("CREATE TABLE IF NOT EXISTS os (hid INT NOT NULL, sid INT NOT NULL, name VARCHAR(255), family VARCHAR(255), generation VARCHAR(255), type VARCHAR(255), vendor VARCHAR(255), accuracy INT)")
	puts "|#{rtv}|#{$!}|".red if @verbose
	dbh.disconnect
	return rtv
end

def insert_os_record(hid,sid,name,family,generation,type,vendor,accuracy)
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	rtv = dbh.do("INSERT INTO os (hid,sid,name,family,generation,type,vendor,accuracy) VALUES ('#{hid}','#{sid}','#{name}','#{family}','#{generation}','#{type}','#{vendor}','#{accuracy}')")
	dbh.disconnect
	return rtv
end

def create_database(db=@database,host=@host,username=@user,passwd=@pass)
	begin
		dbh = DBI.connect("DBI:Mysql:#{db}:#{host}", username, passwd)
		print "Creating the database....".light_yellow if @verbose
		rtv = dbh.do("CREATE DATABASE IF NOT EXISTS #{db}")
		puts "|#{rtv}|#{$!}|".red if @verbose
		dbh.disconnect
	rescue DBI::DatabaseError => e
		if e.message =~ /Unknown database \'#{db}\'/
			raise "Looks like the #{db} database doesn't exist yet, and we don't know how to create it."
		end
	end
	rtv = create_nmap_table(@database, @host, @user, @pass)
	puts "create_nmap_table:RTV: #{rtv}".red if @verbose
	rtv = create_hosts_table(@database, @host, @user, @pass)
	puts "create_hosts_table:RTV: #{rtv}".red if @verbose
	rtv = create_seq_table(@database, @host, @user, @pass)
	puts "create_seq_table:RTV: #{rtv}".red if @verbose
	rtv = create_ports_table(@database, @host, @user, @pass)
	puts "create_ports_table:RTV: #{rtv}".red if @verbose
	rtv = create_os_table(@database, @host, @user, @pass)
	puts "create_os_table:RTV: #{rtv}".red if @verbose

	return rtv
end

def check_scan_record(args, starttime, endtime)
	return_val = false
	starttime = DateTime.strptime(starttime.to_s, "%s")
	endtime = DateTime.strptime(endtime.to_s, "%s")
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	stmt = dbh.prepare("SELECT sid FROM nmap WHERE args='#{args}' AND starttime='#{starttime}' AND endtime='#{endtime}'")
	stmt.execute
	while row=stmt.fetch do
		return_val = row[0] unless row[0].nil? || row[0] == ''
	end
	stmt.finish
	dbh.disconnect
	return return_val
end

def check_host_record(sid,ip4,hostname)
	return_val = false
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	stmt = dbh.prepare("SELECT hid FROM hosts WHERE sid='#{sid}' AND ip4='#{ip4}' AND hostname='#{hostname}'")
	stmt.execute
	while row=stmt.fetch do
		return_val = row[0] unless row[0].nil? || row[0] == ""
	end
	stmt.finish
	dbh.disconnect
	return return_val
end

def seq_record_exists(hid,sid,tcpseq_class,tcpseq_index,tcpseq_values)
	return_val = false
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	stmt = dbh.prepare("SELECT hid FROM sequencing WHERE hid='#{hid}' AND sid='#{sid}' AND tcpclass='#{tcpseq_class}'")
	stmt.execute
	while row=stmt.fetch do
		return_val = true unless row[0].nil? || row[0] == ""
		break
	end
	stmt.finish
	dbh.disconnect
	return return_val
end

def port_record_exists(hid,sid,portnum,portstate,portproto)
	return_val = false
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	stmt = dbh.prepare("SELECT hid FROM ports WHERE hid='#{hid}' AND sid='#{sid}' AND port='#{portnum}' AND state='#{portstate}' AND proto='#{portproto}'")
	stmt.execute
	while row=stmt.fetch do
		return_val = true unless row[0].nil? || row[0] == ""
		break
	end
	stmt.finish
	dbh.disconnect
	return return_val
end

def os_record_exists(sid,hid,osname)
	return_val = false
	dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
	stmt = dbh.prepare("SELECT hid FROM os WHERE hid='#{hid}' AND sid='#{sid}' AND name='#{osname}'")
	stmt.execute
	while row=stmt.fetch do
		return_val = true unless row[0] .nil? || row[0] == ""
		break
	end
	stmt.finish
	dbh.disconnect
	return return_val
end

if @verbose
	puts <<-END

###############
# Input file:		#{input}
# Database:		#{@database}:#{@host}:#{@user}
###############

END

end

nmap = Nmap::Parser.new
if File.exist?(input) && !File.directory?(input) && !File.zero?(input)
	nmap.parsefile(input)
else
	usage(true)
	if !File.exist?(input)
		raise "Input file (#{input}) doesn't exist or not specified.  Nothing to do."
	elsif File.directory?(input)
		raise "Input file (#{input}) appears to be a directory.  I don't know how to handle those (yet)."
	elsif File.zero?(input)
		raise "Input file (#{input}) appears to be zero (0) bytes.  Nothing to do."
	else
		raise "Unhandled error for input file (#{input})."
	end
end

create_database(@database, @host, @user, @pass)

puts nmap.session.inspect.to_s.cyan if @verbose
sid = check_scan_record(nmap.session.scan_args, nmap.session.start_time.to_s, nmap.session.stop_time.to_s)
if sid.is_a?(Integer) && sid > 0
	puts "Scan record already exists.  SID = '#{sid}'" unless @quiet
else
	if @verbose
		pp nmap.session.inspect.to_s.green
	end
	params = {
		:version => nmap.session.nmap_version,
		:xmlversion => nmap.session.xml_version,
		:args => nmap.session.scan_args,
		:types => nmap.session.scan_types,
		:starttime => nmap.session.start_time,
		:startstr => nmap.session.start_str,
		:endtime => nmap.session.stop_time,
		:endstr => nmap.session.stop_str,
		:numservices => nmap.session.numservices
	}
	rtv = insert_nmap_record(params)
	#if rtv != 0; raise "There was a problem inserting the nmap record.  RTV: #{rtv}".red; end
	sid = check_scan_record(nmap.session.scan_args, nmap.session.start_time.to_s, nmap.session.stop_time.to_s)
end

if nmap.hosts.nil? || nmap.hosts.length == 0
    puts "There are no hosts in this scan." unless @quiet
else
	puts "Found hosts in scan." unless @quiet
	nmap.hosts do |host|
		hid = 0
		### check for a host record with this scand id (sid) and
		### the same ip and hostname
		puts "check_host_record(#{sid}, #{host.ip4_addr}, #{host.hostname})" if @verbose
		hid = check_host_record(sid, host.ip4_addr.to_s, host.hostname)
		puts "HID = #{hid}" if @verbose
		if !hid || hid.nil?
			# host record not yet created
			puts "hid is nil, creating...." if @verbose
			puts "#{sid},#{host.ip4_addr},[ip4num],#{host.hostname},#{host.status},#{host.getports(:tcp).length},#{host.getports(:udp).length},#{host.mac_addr},#{host.mac_vendor},#{host.ip6_addr},#{host.distance},#{host.uptime_seconds},#{host.uptime_lastboot}" if @verbose
			rtv = insert_host_record(sid,host.ip4_addr,"[ip4num]",host.hostname,host.status,host.getports(:tcp).length.to_s,host.getports(:udp).length.to_s,host.mac_addr,host.mac_vendor,host.ip6_addr,host.distance,host.uptime_seconds,host.uptime_lastboot)
			#if rtv != 0; raise "There was a problem inserting the host record.  RTV: #{rtv}".red; end
		elsif (hid.is_a?(Integer) || hid.is_a?(Fixnum)) && hid > 0
			# check other scans (get hid/sid)
			dbh = DBI.connect("DBI:Mysql:#{@database}:#{@host}", @user, @pass)
			s = dbh.select_one("SELECT sid,hid FROM hosts WHERE sid='#{sid}' AND hid='#{hid}'")
			dbh.disconnect
			if !s.nil? && (s[0] == sid && s[1] == hid)
				puts "Scan and host already exist.  Skipping." unless @quiet
				#next
			end
		end
		### check for a seq record with this scan id (sid) and
		### tcpseuqence_class, tcpsequence_index, tcpsequence_values
		if seq_record_exists(hid,sid,host.tcpsequence_class,host.tcpsequence_index,host.tcpsequence_values)
			puts "sequencing record exists for scan and host.  skipping...." if @verbose
		else
			rtv = insert_seq_record(hid,sid,host.tcpsequence_class,host.tcpsequence_index,host.tcpsequence_values,host.ipidsequence_class,host.ipidsequence_values,host.tcptssequence_class,host.tcptssequence_values)
			puts "return value for seq record insert: #{rtv}" if @verbose
		end	
		[:tcp, :udp].each do |type|
			host.getports(type) do |port|
				### check for ports reocrd wtih this hid, sid, port num, port state, port name
				if port_record_exists(hid,sid,port.num,port.state,port.service.proto)
					puts "port record exists for scan and host.  skipping...." if @verbose
				else
					if !port.service.fingerprint.nil? && port.service.fingerprint != ""
						port.service.fingerprint.gsub!(/\'/, "&#39;")
					end
					rtv = insert_ports_record(hid,sid,port.num,'',port.state,port.service.name,port.service.tunnel,port.service.product,port.service.version,port.service.extra,port.service.confidence,port.service.method,port.service.proto,port.service.owner,port.service.rpcnum,port.service.fingerprint)
					puts "return value for ports record insert: #{rtv}" if @verbose
				end
			end     # host.getports()
		end     # port types

		### check for os record with this scan id (sid) and host id (hid) and
		### os.name
		if os_record_exists(sid,hid,host.os.name)
			puts "os record exists for scan and host.  skipping...." if @verbose
		else
			rtv = insert_os_record(hid,sid,host.os.name,host.os.osfamily,host.os.osgen,host.os.ostype,host.os.osvendor,host.os.class_accuracy)
			puts "return value for os record insert: #{rtv}" if @verbose
		end
	end     # nmap.hosts loop
end     # if nmap.hosts.nil?


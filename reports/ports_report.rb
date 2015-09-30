#!/usr/bin/env ruby

require 'rubygems'
require 'colorize'
require 'sqlite3'
require 'getoptlong'
require 'pp'

opts = GetoptLong.new(
	['--database', '-d', GetoptLong::OPTIONAL_ARGUMENT ],
)

database = ''
opts.each do |opt,arg|
	case opt
	when '--database'
		database = arg
	end
end

db = SQLite3::Database.new(database)

ports = Array.new
db.execute("SELECT DISTINCT port FROM ports ORDER BY port") do |row|
	ports.push(row[0])
end

hostsByPort = Hash.new
ports.each do |p|
	if !hostsByPort.has_key?(p)
		hostsByPort[p] = Array.new
	end
	db.execute("SELECT h.hid FROM hosts h INNER JOIN ports p ON p.hid=h.hid WHERE p.port='#{p}' AND p.state='open'") do |h|
		if !hostsByPort[p].include?(h[0])
			hostsByPort[p].push(h[0])
		end
	end
end	

pp hostsByPort
puts <<-EOS

<html>
	<head>
		<title>Ports report</title>
	</head>
	<body>
		<div id="main">
			<table border="1">
EOS
hostsByPort.each do |p|
	pp p
	puts "\t\t\t\t<tr><td colspan=\"2\"><h3><b>#{p}</b></h3></td></tr>"
	hostsByPort[p].each do |h|
		r = db.execute("SELECT ip4,hostname FROM hosts WHERE hid='#{h}'")
		puts "\t\t\t\t<tr><td>#{pp r}</td><td>&nbsp;</td></tr>"
	end
end
puts <<-EOS
			</table>
		</div>
	</body>
</html>
EOS


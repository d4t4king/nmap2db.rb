#!/usr/bin/env ruby

require 'rubygems'
require 'colorize'
require 'sqlite3'
require 'getoptlong'
require 'pp'
require 'pdfkit'

def humanize_uptime(uptime)
	[[60, :seconds], [60, :minutes], [24, :hours], [1000, :days]].map{ |count, name|
		if uptime.to_i > 0
			secs, n = uptime.to_i.divmod(count)
			"#{n.to_i} #{name}"
		end
	}.compact.reverse.join(' ')
end

def show_usage
	puts <<-END

#{$0} --help|-h --verbose|-v --database|-d <database_file> --output|-o <output_file.pdf>

--help|-h		Display this useful message
--verbose|-v	Display more verbose output.  Usually used for debugging.
--database|-d	Specify the database file from which to draw data for the report.
--output|-o		Specify the output file.  This program currently only supports PDF
				file format as output.
END

	exit 0
end

opts = GetoptLong.new(
	['--help', '-h', GetoptLong::NO_ARGUMENT ],
	['--verbose', '-v', GetoptLong::NO_ARGUMENT ],
	['--database', '-d', GetoptLong::REQUIRED_ARGUMENT ],
	['--output', '-o', GetoptLong::REQUIRED_ARGUMENT ],
)

verbose = false
database = ''
outputpdf = '/tmp/ports_report.pdf'
opts.each do |opt,arg|
	case opt
	when '--help'
		show_usage
	when '--verbose'
		verbose = true
	when '--database'
		database = arg
	when '--output'
		outputpdf = arg
	end
end

if database.nil? or database == ''
	raise "You must specify a database. \n"
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

#pp hostsByPort
html = "<html>
	<head>
		<title>Ports report</title>
	</head>
	<body>
		<h1 id=\"page_title\">Ports Report: Hosts by open port</h1>
		<div id=\"main\">
			<table border=\"1\">\n"
hostsByPort.each_key do |p|
	#pp p
	html = html + "\t\t\t\t<tr><td colspan=\"2\"><h3><b>#{p}</b></h3></td></tr>\n"
	hostsByPort[p].each do |h|
		r = db.execute("SELECT ip4,hostname FROM hosts WHERE hid='#{h}'")
		r.flatten!
		html = html + "\t\t\t\t<tr><td><a href=\"##{r[0]}\">#{r[0]}</a></td><td>#{r[1]}</td></tr>"
	end
end
html = html + "\t\t\t</table>
		</div>
		<div id=\"hosts\">
			<table border=\"1\">
				<tr><th>IPv4 Address</th><th>Hostname</th><th>Status</th><th># TCP Ports</th><th># UDP Ports</th><th>MAC Address</th><th>MAC Vendor</th><th>IPv6 Address</th><th>Hop Distance</th><th>Uptime</th><th>Last Reboot</th></tr>\n"
db.execute("SELECT ip4,hostname,status,tcpcount,udpcount,mac,vendor,ip6,distance,uptime,upstr FROM hosts") do |rec|
	#pp rec
	html = html + "\t\t\t\t<tr>"
	i = 0
	rec.each do |e|
		if i == 9
			html = html + "<td>" + humanize_uptime(e) + "</td>"
		else
			if i == 0
				html = html + "<td><a name=\"#{e}\">#{e}</a></td>"
			else
				html = html + "<td>#{e}</td>"
			end
		end
		i += 1
	end
	html = html + "</tr>"
end
html = html + "\t\t\t</table>
		</div>			
	</body>
</html>"

#puts html
kit = PDFKit.new(html)
#kit.stylesheets << '/path/to/pdf.css'
kit.to_pdf
kit.to_file(outputpdf)
puts "File saved to #{outputpdf}."


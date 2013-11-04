#!/usr/bin/ruby
# This file is part of adns-ruby library


require 'adns'
require 'pp'

ip_addr=""
if ARGV.length != 1
	$stderr.puts "usage: #{__FILE__} <reverse ip + in-addr.arpa>"
	$stderr.puts "eg: #{__FILE__} 4.4.8.8.in-addr.arpa"
	exit -1
else
	ip_addr = ARGV[0]	
end

puts '* initializing adns..'
adns = ADNS::State.new
puts "* resolving PTR record of address #{ip_addr}.."
q = adns.submit(ip_addr, ADNS::RR::PTR)
pp q.wait()
puts "query status: #{ADNS::status_to_s(q.check[:status])}"

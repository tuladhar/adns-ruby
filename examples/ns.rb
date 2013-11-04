#!/usr/bin/ruby
# This file is part of adns-ruby library


require 'adns'
require 'pp'

domain=""
if ARGV.length != 1
	$stderr.puts "usage: #{__FILE__} <domain>"
	exit -1
else
	domain = ARGV[0]	
end

puts '* initializing adns..'
adns = ADNS::State.new
puts "* resolving NS record of domain #{domain}.."
q = adns.submit(domain, ADNS::RR::NS_RAW)
pp q.wait()
puts "query status: #{ADNS::status_to_s(q.check[:status])}"

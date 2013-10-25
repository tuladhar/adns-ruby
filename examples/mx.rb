#!/usr/bin/ruby
# This file is part of adns-ruby library

require 'rubygems'
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
puts "* resolving MX record of domain #{domain}.."
q = adns.submit(domain, ADNS::RR::MX)
pp q.wait()
puts "query status: #{ADNS::status_to_s(q.check[:status])}"

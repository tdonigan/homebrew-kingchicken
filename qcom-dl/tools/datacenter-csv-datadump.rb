#!/usr/bin/env ruby
# Copyright © 2016 Square, Inc. All rights reserved.
#
# datacenter-csv-datadump.rb
#
# Use this script to dump out conversations from
# datacenter exported csv files.
#
# em@squareup.com
# Jan. 22, 2016

require 'json'

filename = ARGV.shift
if filename.nil?
    puts "usage: #{File.basename $0} file.csv"
    exit!
end

fields = ["Level", "Sp", "Index", "m:s.ms.us", "Dur", "Len", "Err", "Dev", "Ep", "Record", "Data", "Summary", "ASCII"]

File.open(filename) do |f|
    while line=f.gets
        next if line =~ /^#/ # skip comments

        vals = line.chomp.split(',', fields.count)
        hash = Hash[ fields.zip(vals) ]
        next if hash["Record"] !~ /(OUT|IN) txn/ # only dump actual packets

        data = hash.delete("Data")
        ascii = hash.delete("ASCII")
        #puts hash.to_json
        puts "#Data msg_no=#{hash["Index"]} size=#{hash["Len"].inspect} record=#{hash["Record"].strip.inspect}:"
        if data.start_with?("3C 3F 78 6D 6C 20") # "<?xml " hexified
            IO.popen("xxd -r -p", "w") {|io| io.write data}
            puts
        else
            puts "binary: #{ascii}"
            #IO.popen("xxd -r -p | xxd", "w") {|io| io.write data}
        end
        puts
    end
end


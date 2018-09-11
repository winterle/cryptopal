require File.dirname(__FILE__ )+"/SHA1.rb"
require 'openssl'

module SHA1_MAC
   def self.keyed_mac(key, message)
       return SHA1.hexdigest(key+message)
   end
    def self.padding(message)
        fill   = "\x00"*(64 - (message.length+9)%64)
        length = "\x00" * 4 + [message.length*8].pack("N*")
        length.force_encoding("UTF-8")
        padding = ("\x80" + fill + length)
       return padding
    end

end
puts SHA1_MAC.padding("testmsg")
puts SHA1_MAC.keyed_mac("test","msg")

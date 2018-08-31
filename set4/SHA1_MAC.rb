require File.dirname(__FILE__ )+"/SHA1.rb"
require 'openssl'

module SHA1_MAC
   def self.mac(key, message)
          return SHA1.hexdigest((key+message).force_encoding("UTF-8"))
   end
    def self.padding(message)
        #???
        puts message.length
    end


end

def test


end

test


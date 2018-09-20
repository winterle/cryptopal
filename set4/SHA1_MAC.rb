require File.dirname(__FILE__ )+"/SHA1.rb"
require 'openssl'

module SHA1_MAC
    #return the SHA1-MAC for a key and a message
   def self.keyed_mac(key, message)
       return SHA1.hexdigest(key+message)
   end

   #takes key, actual message and a custom padding and returns the SHA1-hash (MAC)
   # doesn`t append any new padding, returns the registers instead of hex value
   def self.keyed_mac_padding(key,message,padding)
       return SHA1.hexdigest_nopadding(key+message+padding)
   end
    #@return SHA1-padding for @param message
    def self.padding(message)
        fill   = "\x00"*(64 - (message.length+9)%64)
        length = "\x00" * 4 + [message.length*8].pack("N*")
        length.force_encoding("UTF-8")
        padding = ("\x80" + fill + length)
       return padding
    end

    #splits a SHA1-mac into 32 bit registers
    def self.split_registers(mac)
        if mac.length != 40
            raise "wrong sha1-mac digest length"
        end
        registers = []
        (0...40).step(8) do |register_no|
            res = 0
            (0...8).each do |pos|
                res = res << 4
                res+= mac[register_no+pos].to_i(16)
            end
            registers.append(res)
        end
        return registers
    end

    def self.run
        mac = SHA1_MAC.keyed_mac("secretkey","comment1=cooking
        %20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
        puts "mac is: "
        puts mac
        puts "forged mac (of message = key||actual message||glue-padding||additional message||padding) is:"
        registers = SHA1_MAC.split_registers(mac)
        puts SHA1.hexdigest(";admin=true",registers)

    end

end





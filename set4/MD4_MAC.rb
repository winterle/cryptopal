require_relative 'MD4.rb'


module MD4_MAC
    #prepends the 'secret' key
    def self.keyed_mac(string)
        key = "verysecretkey"
        res = md4(key+string).unpack('H*').join
        return res
    end

    def self.run
        mac = self.keyed_mac("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
        registers = self.split_registers(mac)
        #feed the registers to the MD4-function as magic values and the additional message will appear to be hashed under the same secret key
        forged_mac = md4(";admin=true",registers[0],registers[1],registers[2],registers[3]).unpack('H*')
        puts "forged mac:"
        puts forged_mac

    end

    def self.split_registers(mac)
        registers = []
        (0...4).each do |reg|
            sub = mac[reg*8,8]
            registers.append(sub.to_i(16))
        end
        return registers
    end

end
MD4_MAC.run

require 'openssl'
require "#{File.dirname(__FILE__ )}/../set2/cbc.rb"
require "#{File.dirname(__FILE__ )}/../set2/padding_validation.rb"

module CBC_key_recover
    $key = OpenSSL::Random.random_bytes(16)
    $iv = $key

    def CBC_key_recover.encrypt(plain)
        plain.gsub!(/[;=]/,'') #remove control characters
        pre = "comment1=cooking%20MCs;userdata="
        post = ";comment2=%20like%20a%20pound%20of%20bacon"
        all = pre+plain+post
        cipher = CBC.encrypt(all,$key,$iv,16)#this also adds pks7 padding
        return cipher
    end

    def CBC_key_recover.decrypt(cipher) #also checks for high-ascii values and raises an error on encountering such
        plain = CBC.decrypt(cipher,$key,$iv,16)
        plain = Padding_validation.validate(plain,16)
        (0...plain.size).each do |i|
            if plain[i].ord > 127
                raise "invalid chars: "<<plain #rip
            end
        end
        if plain.match?(/;admin=true;/)
            puts("admin query")
            return true
        else
            puts("user query")
            return false
        end
    end

    def self.crack_key(cipher)
        #abusing the intermediate state before xor to reconstruct
        # the iv == key :)
        (16...32).each do |i|
            cipher[i] = 0x00.chr
        end
        (32...48).each do |i|
            cipher[i] = cipher[i-32]
        end
        begin
        plain = CBC_key_recover.decrypt(cipher)
        rescue RuntimeError => invalid_plain
            invalid_plain = invalid_plain.to_s
            offset = "invalid chars: ".size
            ret_key = []
            (0+offset...16+offset).each do |i|
                ret_key.push((invalid_plain[i].ord ^ invalid_plain[i+32].ord).chr)
            end
            return ret_key.join
        end
        raise "decryption unsuccessful"
    end

end
#run
cipher = CBC_key_recover.encrypt("some very secret userdata")
key = CBC_key_recover.crack_key(cipher)
puts "recovered key:\n#{key}"
puts "actual used key:\n#{$key}"

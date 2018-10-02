require_relative '../set5/rsa'
require 'openssl'

class RSA_decrypt_service < RSA

    #overwrite decrypt func to reflect the timestamp behaviour
    def decrypt(int)
        if @d.nil?
            raise 'call keygen first'
        end
        if @hashlist.nil?
            @hashlist = []
        end
        plain = modexp(int,@d,@n)
        str = int_to_str(plain)
        #check, if hash is already in 'database'
        sha256 = OpenSSL::Digest.new('sha256')
        sha256 << str
        digest = sha256.hexdigest
        if @hashlist.include?(digest)
            return nil
        end
        #keep hash
        @hashlist.push(digest)
        return plain
    end
end

dec = RSA_decrypt_service.new
dec.keygen
cipher = dec.encrypt('some message')
#server decrypts the message once, hash is now saved
puts "server decoded:"
puts int_to_str(dec.decrypt(cipher))
puts "\ntrying to decode again: (server returns nil)"
puts dec.decrypt(cipher).class
#attacker gets hold of cipher
pub = dec.get_pub #[e,n] (public info)
s = 2
cipher_forged = (modexp(s,pub[0],pub[1])*cipher)%pub[1]
plain_forged = dec.decrypt(cipher_forged)
plain = ((plain_forged)*invmod((s),pub[1]))%pub[1]
puts "\nrecovered:"
puts int_to_str(plain)



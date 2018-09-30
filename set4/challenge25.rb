require'openssl'
require File.dirname(__FILE__ )+"/../set3/ctr.rb"


module RA_RW_AES_CTR #random access read write
    f = File.read("#{File.dirname(__FILE__ )}/../set1/7.dat")
    f = f.unpack('m').join #base64
    dec = OpenSSL::Cipher.new('AES-128-ECB')
    dec.decrypt
    dec.key = 'YELLOW SUBMARINE'
    plain = dec.update(f) + dec.final
    $key = OpenSSL::Random.random_bytes(16)
    $nonce = OpenSSL::Random.random_bytes(16)
    cipher = CTR.ctr(plain,$key,$nonce.dup)
    def self.edit(cipher,key,offset,plain_newtext,nonce)#warning: this alters the content of nonce (pass by reference), if you need that initial nonce again, pass a duplicate!
        keystr = 0
        (0...offset).step(16) do
            keystr = CTR.keystream(key,nonce)
            nonce[8] = ((nonce[8].ord + 1)%256).chr
        end
        (offset...offset+plain_newtext.size).each do |i|#insert actual new text
            if i%16==0
                keystr = CTR.keystream(key,nonce)
                nonce[8] = ((nonce[8].ord + 1)%256).chr
            end
            cipher[i] = (plain_newtext.ord ^ keystr[i%16].ord).chr
        end
        return cipher
    end
    def self.edit_api(cipher,offset,plain_newtext)#exposed to attacker, doesn't reveal key nor plaintext
        return edit(cipher,$key,offset,plain_newtext,$nonce.dup)
    end


    def self.break(cipher)
        #we achieve linear complexity by editing char by char, comparing against the original cipher.
        #whenever the encrypted original cipher[char_index]==altered_cipher[char_index] we decrypted a char
        old_cipher = cipher.dup
        plain = ''
        (0...cipher.size).each do |char_index|
            puts "index = #{char_index}"
            (0...256).each do |char| #could definitely speed this up a lot by trying the chars in dictionary frequency
                cipher = edit_api(cipher, char_index, char.chr)
                if cipher[char_index] == old_cipher[char_index]
                    plain << char.chr
                    puts "success"
                    break
                end
            end

        end
        return plain
    end
    #run
     puts RA_RW_AES_CTR.break(cipher)

end


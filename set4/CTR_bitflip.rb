require 'openssl'
require File.dirname(__FILE__ )+"/../set3/ctr.rb"

#some copy pasta with refactoring dessert from set2/bitflip.rb
module CTR_bitflip
  $key = OpenSSL::Random.random_bytes(16)
  $nonce = OpenSSL::Random.random_bytes(16)

  def self.encrypt(plain)
    plain.gsub!(/[;=]/,'') #remove control characters
    pre = "comment1=cooking%20MCs;userdata="
    post = ";comment2=%20like%20a%20pound%20of%20bacon"
    all = pre+plain+post
    cipher = CTR.ctr(all,$key,$nonce.dup)
    return cipher
  end

  def self.decrypt(cipher)
    plain = CTR.ctr(cipher,$key,$nonce.dup)
    if plain.match?(/;admin=true;/)
      puts("admin query")
      return true
    else
      puts("user query")
      return false
    end
  end

  def self.modify
    admin = (0x00).chr<<"admin"<<(0x00).chr<<"true"<<(0x00).chr
    #find user input start index
    cipher1 = encrypt('a')
    puts "before:"
    decrypt(cipher1)
    cipher2 = encrypt('b')
    start = -1
    (0...cipher2.size).each do |i|
        if cipher2[i] != cipher1[i]
            start = i
            break
        end
    end
    if start == -1
        raise "is this ctr mode?"
    end
    #since we encrypted 0x00 at the positions we want to have our control characters, the cipher[index] = xorstream[index]
    # so we can just do cipher[index] XOR control_character and we already have our control character encrypted :)
    cipher1 = encrypt(admin)
    cipher1[start] = (cipher1[start].ord ^ ';'.ord).chr
    cipher1[start+"Aadmin".size] = (cipher1[start+"Aadmin".size].ord ^ '='.ord).chr
    cipher1[start+"AadminAtrue".size] = (cipher1[start+"AadminAtrue".size].ord^';'.ord).chr
    #and done
    puts "after:"
    decrypt(cipher1)

  end
    modify
end

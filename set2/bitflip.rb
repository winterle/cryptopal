require 'openssl'
require "#{File.dirname(__FILE__ )}/cbc.rb"
require "#{File.dirname(__FILE__ )}/padding_validation.rb"

module Bitflip
  $key = (0x00).chr * 16#OpenSSL::Random.random_bytes(16)
  $iv = (0x00).chr * 16#OpenSSL::Random.random_bytes(16)

  def Bitflip.encrypt(plain)
    plain.gsub!(/[;=]/,'') #remove control characters
    pre = "comment1=cooking%20MCs;userdata="
    post = ";comment2=%20like%20a%20pound%20of%20bacon"
    all = pre+plain+post
    cipher = CBC.encrypt(all,$key,$iv,16)#this also adds pks7 padding
    return cipher
  end

  def Bitflip.decrypt(cipher)
    plain = CBC.decrypt(cipher,$key,$iv,16)
    plain = Padding_validation.validate(plain,16)
    if plain.match?(/;admin=true;/)
      puts("admin query")
      return true
    else
      puts("user query")
      return false
    end
  end

  def Bitflip.modify
    admin = (0x00).chr<<"admin"<<(0x00).chr<<"true"<<(0x00).chr
    # we want to change the block before to change the 0x00's to our wanted symbols
    #first, search for the block where our admin string is
    cipher1 = Bitflip.encrypt('a'*32 << admin)
    cipher2 = Bitflip.encrypt('a'*16<<'b'<<'a'*15<<admin)
    puts "before: "
    decrypt(cipher1)
    start = -1
    (0...cipher1.size).each do |i|
      if cipher1[i] != cipher2[i]
        start = i
        break
      end
    end
    if start == -1
      raise "failed @modify, is this CBC?"
    end
    #start should now be the index of the block we change to flip bits in our admin block
    cipher1[start] = (cipher1[start].ord^';'.ord).chr
    cipher1[start+"adminAtrueA".size] = (cipher1[start+"adminatrueA".size].ord^';'.ord).chr
    cipher1[start+"adminA".size] = (cipher1[start+"adminA".size].ord ^'='.ord).chr
    puts "after: "
    decrypt(cipher1)

  end

end
#run
#Bitflip.modify
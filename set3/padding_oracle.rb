require 'openssl'
require "#{File.dirname(__FILE__ )}/../set2/padding_validation"
require "#{File.dirname(__FILE__ )}/../set2/cbc.rb"

module Padding_oracle
  $strings = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
              "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
              "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
              "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
              "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
              "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
              "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
              "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
              "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
              "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]


  $key = OpenSSL::Random.random_bytes(16)
  $iv = OpenSSL::Random.random_bytes(16)
def self.encrypt
  str = $strings[rand(10)].unpack('m').join

  cipher = CBC.encrypt(str,$key,$iv,16)
  return cipher
end

def self.decrypt(cipher,iv)
  plain = CBC.decrypt(cipher,$key,iv,16)
  Padding_validation.validate(plain,16) #this method raises an error when encountering faulty padding :) (even the openssl lib would do so)
end

def self.break_block(cipher) #returns the intermediate state for the given block
  if cipher.size != 16
    raise "one block of size 16 please"
  end
  iv = 'a'*16
  is = 'a'*16
  (0...16).reverse_each do |index|
    (index+1...16).each do |new|
      iv[new] = ((16-index)^is[new].ord).chr
    end
    (0...256).each do |c|
     iv[index] = c.chr
      begin
        decrypt(cipher,iv)
      rescue RuntimeError #whenever the padding is not valid after decryption, a RuntimeError is thrown. By catching it we can find the iv-byte to produce valid padding
        next
      end
      puts"--found--"
      is[index] = (c.ord^(16-index).ord).chr
      puts "intermediate state[#{index}] = (#{c}) xor (#{16-index}) = (#{is[index].ord}) ; as char = #{is[index]}"
      break
    end
  end
  return is


end


def self.break_all
  str = Padding_oracle.encrypt
  last_block = $iv
  plain_all = ""
  (0...str.size).step(16) do |block_index|
    is = Padding_oracle.break_block(str[block_index,16])
    (0...16).each do |i|
     plain_all<<(last_block[i].ord^is[i].ord).chr
    end
    last_block = str[block_index,16]
  end
  puts Padding_validation.validate(plain_all,16) #remove the padding (ruby is really annoying w/ padded strings and sometimes just doesn't print them)
end

end
#uncomment me
#Padding_oracle.break_all
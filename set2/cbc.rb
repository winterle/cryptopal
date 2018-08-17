require'openssl'
#not required for decryption:
require "#{File.dirname(__FILE__ )}/pkcs7.rb"


#implementation of CBC (using AES-128 for single block en/decryption)
module CBC

def CBC.aes_128_encrypt(plain,key)
  if key.length != 16
    raise "key length must be 16"
  end
  enc = OpenSSL::Cipher.new('AES-128-ECB')
  enc.encrypt #remember: this needs to be the first call after creation, since it resets all settings
  enc.padding = 0 #need this?
  enc.key = key
  cipher = enc.update(plain) + enc.final
  return cipher
end

def CBC.aes_128_decrypt(cipher,key)
  if key.length != 16
    raise "key length must be 16"
  end
  dec = OpenSSL::Cipher.new('AES-128-ECB')
  dec.decrypt
  dec.padding = 0
  dec.key = key
  plain = dec.update(cipher) + dec.final
  return plain
end

def CBC.xorchars(char1,char2)
  return (char1.ord^char2.ord).chr
end

def CBC.encrypt(plain,aes_ecb_key,iv,block_length)
  plain = Pkcs7.pad(plain,16)
  last_block = iv
  cipher = ''
  cipher.clear
  (0...plain.size).step(block_length) do |block_index|
    (0...block_length).each do |char_index|
      plain[block_index+char_index] = xorchars(plain[block_index+char_index],last_block[char_index])
    end
    last_block = aes_128_encrypt(plain[block_index,block_length],aes_ecb_key)
    cipher << last_block
  end
  return cipher
end

def CBC.decrypt(cipher,aes_ecb_key,iv,block_length)
  plain = ''
  plain.clear
  last_block = iv
  res = []
  (0...cipher.size).step(block_length) do |index|
    dec = CBC.aes_128_decrypt(cipher[index,block_length],aes_ecb_key)
    (0...16).each do |i|
      res.append(xorchars(dec[i],last_block[i]))
    end

    last_block = cipher[index,block_length]

    plain << res.join
    res.clear
  end
return plain
end

def CBC.decrypt_dat
  block_length = 16
  iv = 0x00.chr * 16

  f = File.read("#{File.dirname(__FILE__ )}/cbc.dat")
  f = f.unpack('m').join
  key = 'YELLOW SUBMARINE'

  plain = decrypt(f,key,iv,block_length)
  puts(plain)
end
end
#uncomment to run
#CBC.decrypt_dat

#testing
=begin
key = 'abcdefghasdfjkll'
c = CBC.encrypt("ABCDHEELOasda553dx",key,(0x00).chr*16,16) #test
puts c
p = CBC.decrypt(c,key,(0x00).chr*16,16)
puts p
=end
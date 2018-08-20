
require 'openssl'

$str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".unpack('m').join


module CTR

  def self.ctr(plain,key,nonce)
    keystr =''
    cipher = ''
    (0...plain.size).each do |i|
      if i%16==0
        keystr = keystream(key,nonce)
        nonce[8] = ((nonce[8].ord + 1)%256).chr
      end
      cipher << (plain[i].ord^keystr[i%16].ord).chr
    end
    return cipher
  end
  def self.keystream(key,nonce)
    enc = OpenSSL::Cipher.new('AES-128-ECB')
    enc.encrypt
    enc.padding = 0
    enc.key = key
    return enc.update(nonce)<<enc.final
  end
end
=begin encrypt / decrypt "hello"
c = CTR.ctr("hello",'YELLOW SUBMARINE', 0x00.chr*16)
puts c
puts CTR.ctr(c,'YELLOW SUBMARINE', 0x00.chr*16)
=end

#uncomment me
#puts CTR.ctr($str,'YELLOW SUBMARINE',0x00.chr*16)

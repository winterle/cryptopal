require'openssl'
f = File.read("#{File.dirname(__FILE__ )}/7.dat")
f = f.unpack('m').join #base64
dec = OpenSSL::Cipher.new('AES-128-ECB')
dec.decrypt
dec.key = 'YELLOW SUBMARINE'
puts(dec.update(f) + dec.final)
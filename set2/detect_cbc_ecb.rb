require'openssl'
module Detect_ecb

def Detect_ecb.oracle(plain)
  #prepend and extend by 5..10 random bytes
  i = rand(5) + 5 # in range (5..10)
  while i >= 0
    plain = (rand(256)).chr + plain
    i-=1
  end
  i = rand(5) + 5 #in range (5..10)
  while i >= 0
    plain = plain + (rand(256)).chr
    i-=1
  end

  if rand(2) == 0
    enc = OpenSSL::Cipher.new('AES-128-CBC')
    puts "was CBC"
  else
    enc = OpenSSL::Cipher.new('AES-128-ECB')
    puts "was ECB"
  end
  enc.encrypt
  enc.key = OpenSSL::Random.random_bytes(16)
  enc.random_iv

  cipher = enc.update(plain)+enc.final
  return cipher.unpack('H*').join
end

def Detect_ecb.enc(cipher,block_len)
stack =[]
  (0..cipher.length).step(block_len) do |i|
    block = cipher[i...i+block_len]
    if stack.include?(block)
      return true
    end
    stack.push(block)
  end
  return false

end

def Detect_ecb.run #run this to solve the challenge
  plain = 'b'*200
  c = Detect_ecb.oracle('test'+plain)
  if Detect_ecb.enc(c,16)
    puts 'ECB detected'
  else
    puts 'probably CBC, or no identical blocks encrypted'
  end
end

end

#uncomment to run
#Detect_ecb.run
require 'openssl'
require File.dirname(__FILE__)+"/MT19937_mersenne_twister_RNG"

class MT19937_cipher
  def initialize(key)
    if key.bit_length > 16
      raise "wrong key length, has to be 16 bit long"
    end
    @prng = MT19937.new(key)
  end
  def en_de_crypt(message)
    res = []
    keystream = nil
    (0...message.size).each do |i| #prng outputs 4 byte of 'random' data, that we use for 4 consecutive bytes and then refresh the keystream (get a new 'rand' number)
      if i%4==0
        keystream = @prng.number
        res.push((message[i].ord ^ (keystream & 0xFF)).chr)
      end
      if i%4==1
        res.push((message[i].ord ^ ((keystream >> 8) & 0xFF)).chr)
      end
      if i%4==2
        res.push((message[i].ord ^ ((keystream >> 16) & 0xFF)).chr)
      end
      if i%4==3
        res.push((message[i].ord ^ ((keystream >> 24) & 0xFF)).chr)
      end
    end
    return res.join
  end

end
module MT19937_cipher_break
  def self.encrypt(message) #encrypt under random 'key', save key for checking if the broken 'key' is correct
    message = OpenSSL::Random.random_bytes(rand(10)+1) + message # prepend a rand number of bytes between 1 and 10
    key = (OpenSSL::Random.random_bytes(1).ord << 8 ) | OpenSSL::Random.random_bytes(1).ord
    $key = key
    enc = MT19937_cipher.new(key)
    cipher = enc.en_de_crypt(message)
    return cipher
  end
  def self.break_seed
    #known plaintext: discover key by corresponding cipher
    cipher = encrypt('A'*14)
    #pure brute force
    (0...2**16).each do |try_seed|
      enc = MT19937_cipher.new(try_seed)
      cipher2 = enc.en_de_crypt(('z'*(cipher.size-14)) << 'A'*14)
      ((cipher2.size-14)...(cipher2.size)).each do |i|
        if cipher2[i] != cipher[i]
          break
        end
        if cipher2[i] == cipher[i] && i == cipher2.size-1
          puts "found (dec): #{try_seed}"
          puts "real seed was #{$key}"
          return
        end
      end
    end
  end
end

module MT19937_password_reset
  def self.reset_token
    enc = MT19937.new(Time.now.to_i)
    return enc.number
  end
  def self.check_token(token,time_frame)#time frame is how old the token is allowed to be in seconds (relative value)
    time = Time.now.to_i
    (time-time_frame..time).each do |seed|
      enc = MT19937.new(seed)
      if token == enc.number
        return true
      end
    end
    return false
  end
end
#uncomment me
#MT19937_cipher_break.break_seed
token = MT19937_password_reset.reset_token
sleep(rand(15)+1)
if MT19937_password_reset.check_token(token,30)
  puts "token was a product of a MT19937 PRNG seeded recently with the current time"
else
  puts "token was not a product of a MT19937 PRNG (or has expired)"
end

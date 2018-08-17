require'openssl'
require "#{File.dirname(__FILE__ )}/detect_cbc_ecb"


$secret_b64= 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK' #unencrypted

module Rand_prefix_ecb
  $key = OpenSSL::Random.random_bytes(16)
  $secret = $secret_b64.unpack('m').join #now a string we want to crack (after it's encrypted)

  def Rand_prefix_ecb.encode(input) #key will be static random (during runtime), random bytes different every time, this function is a 'blackbox' for us
    rand_prefix = OpenSSL::Random.random_bytes(rand(99)+1)
    plain = rand_prefix+input+$secret
    enc = OpenSSL::Cipher.new('AES-128-ECB')
    enc.encrypt
    enc.key=$key
    return (enc.update(plain) + enc.final)
  end

  def Rand_prefix_ecb.break #FIXME sometimes fails (decrypts a byte wrong and gets stuck in an endless loop)

  block_len = 16
  cipher = Rand_prefix_ecb.encode('b'*block_len*3)

  #put in 3* the same block, so we know for sure which one it is and save it for later use
  stack = []
  stat_block = nil
  (0..cipher.size).step(block_len) do |block_index|
    stat_block = cipher[block_index,block_len]
    if stack.include?(stat_block)
      puts "found dup injected block, index is #{block_index/16}"
      break
    end
    stack.push(stat_block)
  end
  #puts stat_block
  #now we know how 'b'*16 looks like encrypted
  # now we just run the normal byte-at-a-time attack, but only validate the results of an encryption whenever we see our known block
  # because that means, the blocks are aligned in our favor (this increases complexity by static factor block_length)

  input = 'a' * cipher.length #some number >= attacked bytes count
  length = cipher.length
  secret = ''
  stack = []
  redo_flag = false

  for i in (1..cipher.length)
    for j in (0...256) #each possible char
      input[length-1] = j.chr
      cipher = Rand_prefix_ecb.encode(('b'*block_len)+input)

      #this checks for correct alignment by searching for the stat_block
      if !(cipher.include?(stat_block))
        redo
      end
      start = cipher.index(stat_block) + length
      if start%16 > 0
        redo
      end

      #this is our input string encrypted block
      stack.push(cipher[start,block_len])
    end

    #find the actual cipher
    loop do
      actual = Rand_prefix_ecb.encode(('b'*block_len)+input[0,length-i])

      #this checks for correct alignment by searching for the stat_block
      if !(actual.include?(stat_block))
        redo
      end
      start = actual.index(stat_block) + length
      if start%16 > 0 #this will probably never happen, but it's nice to have anyways
        redo
      end
        char = stack.find_index(actual[start,block_len])


      stack.clear
      if char.nil? || char > 255
        redo_flag = true
        break
      else if char == 0x01
             puts "secret decrypted:\n"<<secret
             return secret
           end
      end


      input = input[1..input.size-2]
      input << char.chr << 'a'
      secret << char.chr
      putc(char.chr)
      break

    end

    if redo_flag
      stack.clear
      redo_flag = false
      redo
    end
  end

  end

end
#uncomment me
#Rand_prefix_ecb.break
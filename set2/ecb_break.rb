require'openssl'
require "#{File.dirname(__FILE__ )}/detect_cbc_ecb"

$secret_b64= 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK' #unencrypted

module Break_ecb
  $key = OpenSSL::Random.random_bytes(16)
  $secret = $secret_b64.unpack('m').join #now a string we want to crack (after it's encrypted)

  def Break_ecb.encode(input) #key will be static random (during runtime), this function is a 'blackbox' for us
    plain = input+$secret
    enc = OpenSSL::Cipher.new('AES-128-ECB')
    enc.encrypt
    enc.key=$key
    return (enc.update(plain) + enc.final)
  end

  def Break_ecb.detect
    (0..256).step(16) do |length|
      cipher = Break_ecb.encode(('a'*length))
      if Detect_ecb.enc(cipher,16)
        return length/2
      end
    end
    return 0
  end

  def Break_ecb.break_all
    input = 'a' * Break_ecb.encode('').size
    secret = ''
    stack = []

    (0...input.size).each do |char_index| #each position
      char_reverse_index = (input.size-1)-char_index
      (0..255).each do |char_try| #each possible char
        input[input.size-1] = char_try.chr
        stack.push(Break_ecb.encode(input)[0,input.size])
      end

      if (char = stack.find_index(Break_ecb.encode('a'*char_reverse_index)[0,input.size])) != nil
        secret << char.chr
        input = 'a'* (char_reverse_index - 1)
        input << secret
        input << 'a'
      else
        if stack.include?(Break_ecb.encode('a'*input.size)[0,input.size])
          puts "padding"
        end
        puts "--- (non-fatal error, recoverable) probably padding related ---\n--- found so far: ---\n#{secret}"
        return
      end
      stack.clear
    end
    puts "--- decrypted: --- \n#{secret}"
  end

  def Break_ecb.solution #run to solve
    block_len = Break_ecb.detect
    if block_len > 0
      puts "--- Mode is ECB, Block length is #{block_len} ---"
    else
      raise "--- (fatal) Cannot break non-ECB mode ---"
    end
    Break_ecb.break_all
  end
end
#uncomment me, i want to be free :)
#Break_ecb.solution

require 'openssl'
require "#{File.dirname(__FILE__ )}/detect_cbc_ecb"

module Modify_ecb
  #$static_rand_key = 'b' *16 #TESTING, remove!

  $static_rand_key = OpenSSL::Random.random_bytes(16)

  def Modify_ecb.profile_for(input)#does not allow control characters (eg. &,=), 'client side'
    input.gsub!(/[&=]/,'')
    output = "email=#{input}&uid="<<55.to_s<<"&role=user"
    return enc(output)
  end


  def Modify_ecb.enc(input)#' client side'
    enc = OpenSSL::Cipher.new('AES-128-ECB')
    enc.encrypt
    enc.key = $static_rand_key
    return enc.update(input) << enc.final

  end

  def Modify_ecb.dec_parse(cipher) #'server side'
    dec = OpenSSL::Cipher.new('AES-128-ECB')
    dec.decrypt
    dec.key = $static_rand_key
    plain = dec.update(cipher) << dec.final
    return parse(plain)
  end

  def Modify_ecb.parse(input)#'server side'
    output = "{\n"
    params = input.scan(/[^&=]+=[^&]*/)
    (0...params.size).each do |i|
      output << "\t"<< params[i].scan(/^[^=]*/).join<<": '"<<params[i].scan(/[^=&]*\Z/).join<<"',\n"
    end
    output << "}"
    return output
  end

  def Modify_ecb.block_len
    #push chars until cipher length changes
    oldlen = newlen = Modify_ecb.profile_for('').size
    i = 0
    while true
      cipher = Modify_ecb.profile_for('a'*i)
      newlen = cipher.size
      if newlen > oldlen
        return newlen-oldlen
      end
      i+=1
    end

  end


  def Modify_ecb.generate_admin #attacker
    #goal: generate a cipher that decrypts to a valid role=admin profile using only the client side available profile_for()
    # &role=admin is in the last encrypted block, so if we can manage to align the last block with the &rule=, we can put
    # an encrypted block containing admin there

    #first, we determine the block length
    block = block_len
    puts "--- block length is #{block} bytes ---"
    if Detect_ecb.enc(profile_for('a'*(3*block)),block) #because even if our test string is misaligned in the middle of the cipher, we can detect ecb
      puts "--- ECB detected ---"
    else raise "this script is not for non-ECB mode"
    end

    admin = "admin"<<((block_len-"admin".size).chr)*(block_len-"admin".size) #admin and valid padding to fill the block, now encrypt it

    #too lazy to find out that there is a static email= string in the beginning, but would be rather easy by
    # encrypting a few profiles and seeing how many chars it takes to produce different changing blocks...
    cipher = profile_for('a'*(block_len-("email=".size))<<admin)
    admin_enc = cipher[block_len,block_len]

    #now, increase email string size to produce a fully padded block
    size = 999999
    for i in 0...16
      enc = profile_for("ha"<<'X'*i<<"0r@dom.com")
      if enc.size > size
        size = i
        break
      end
      size = enc.size
    end
    enc = profile_for("ha"<<'X'*size<<"0r@dom.com")
    #enc now has the last block valid padding, replace that with the prepared admin and we should get something like ...&role=useradmin
    enc = enc[0,enc.size-block_len]
    enc << admin_enc

    #didnt come up with a way to tell the length of the role field ('user'.size), just have to try it out
    while true
      enc = profile_for("ha"<<'X'*(size%16)<<"0r@dom.com")
      enc = enc[0,enc.size-block_len]
      enc << admin_enc
      if dec_parse(enc).scan(/role: 'admin'/)[0] != nil
        break
      end
      size +=1
    end

    puts"----\nencrypted string\n"
    for i in 0...enc.size #null terminator can be annoying :P
      putc(enc[i])
    end
    puts"\ndecrypts to\n#{dec_parse(enc)}\n----"

  end

end
  #uncomment to run
  #Modify_ecb.generate_admin
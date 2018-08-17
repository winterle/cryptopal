

module Padding_validation

  def Padding_validation.validate(plain,block_len)
    if (plain.size % 16) > 0
  raise "invalid padding"
    end
    last_block = plain[plain.size - block_len, block_len]

    reference = last_block[block_len-1].ord

    if reference > block_len || reference == 0
      raise "invalid padding"
    end

    (block_len-reference...block_len).each do |pos|
      if last_block[pos].ord == reference
        #puts "ok"
      else
        raise "invalid padding"
      end
    end
    return plain[0,plain.size-reference]


  end


end
=begin
plain = "ICE ICE BABY" << (0x04.chr)*4
puts Padding_validation.validate(plain,16)
=end
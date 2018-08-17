


class MT19937 #32-bit implementation


  def initialize(seed)
    @wordsize = 32
    @state_size = 624
    @state = []
    @lower_mask = (1<<(@wordsize-1))-1 # binary: r * 1 (sequence)
    @higher_mask =  (~@lower_mask)&((1<<@wordsize)-1) # negate lower_mask, take lower 32 (wordsize) bits
    @index = @state_size
    @state.push(seed)
    (1...@state_size).each do |i|
      @state.push((1812433253 * (@state[i-1]^(@state[i-1] >> (@wordsize-2))) + i))
    end
  end
  def number
    if @index == @state_size #internal state completely used up
      change_state
    else if @index > @state_size
      raise "MT19937 not seeded"
    end
    end
    y = @state[@index]
    y = y ^ ((y >> 11) & 0xFFFFFFFF)
    y = y ^ ((y << 7) & 0x9D2C5680)
    y = y ^ ((y << 15) & 0xEFC60000)
    y = y ^ (y >> 43)
    @index+=1
    y = (y & ((1<<@wordsize)-1))
    return y #lower @wordsize bits of the derived y
  end
  def change_state
    (0...@state_size).each do |i|
      x = (@state[i] & @higher_mask) + (@state[(i+1)%@state_size] & @lower_mask)
      x_a = x >> 1 #twist matrix
      if x%2 != 0
        x_a = x_a ^ 0x9908B0DF
      end
      @state[i] = @state[(i+(@wordsize-1))%@wordsize] ^ x_a
    end
    @index = 0
  end

end
#rng = MT19937.new(2552)
#(0..6666).each do |i|
#  puts rng.number
#end

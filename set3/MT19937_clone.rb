
require(File.dirname(__FILE__)+"/MT19937_mersenne_twister_RNG")

class Dup < MT19937
  def set_state(state)
    @state = state
    @index = 624
  end
end

module MT19937_clone

def self.untemper(rng_output)
  #puts "bitsize is #{rng_output.bit_length}"
  x = rng_output
  x = x ^ (x>>18)
  x = x ^ (( x << 15) & 0xEFC60000)
  (0..(rng_output.bit_length/7)+2).each do
    x = x ^ ((x << 7)& 0x9D2C5680)
  end
  (0..(rng_output.bit_length/11)+4).each do
    x = x ^ (x >> 11)
  end
  return x
end
#returns a new instance of the MT19937 class that produces the same sequence
def self.clone(rng_instance)
  state = []
  begin
  (0...624).each do |i|
    state.push(untemper(rng_instance.number))
  end
  rescue NoMethodError
    raise "please pass an instance of the MT19937 class"
  end
  ret = Dup.new(0)
  ret.set_state(state)
  return ret
end

rng = MT19937.new(Time.now.to_i)
cloned = clone(rng)
  #these two should now produce the same number sequence
  (0..700).each do |i|
    c = cloned.number
    r = rng.number
    if c != r
      puts r
      puts c
      puts "failed miserably at index #{i}"
      exit(-1)
    end
  end
  puts "success!"


end



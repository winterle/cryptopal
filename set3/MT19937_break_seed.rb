require File.dirname(__FILE__ )+"/MT19937_mersenne_twister_RNG.rb"





module Seed
  def self.generate #waits a number of seconds, then seeds a new instance of a MT19937, waits a random number of seconds again and returns the first number
    #sleep(rand(960)+40)
         puts "working, this take a while..."
    rand = MT19937.new($timestamp = Time.now.to_i) #seed with current unix timestamp, save for validating the recovered seed
    sleep(rand(335)+1)
    return rand.number
  end
  def self.recover_seed(first_number_output)

    time = Time.now.to_i
    i = 0
    while true
      if i > 20000
        raise "RNG seeded too long ago"
      end
      rand = MT19937.new(time)
      if rand.number == first_number_output
        return time
      end
      time -=1
      i+=1
    end
  end
end
first_number = Seed.generate
seed = Seed.recover_seed(first_number)
puts "recovered seed is #{seed}"
puts "real seed was #{$timestamp}"
if seed == $timestamp
  puts "recover was sucessful"
else
  puts "failed"
end
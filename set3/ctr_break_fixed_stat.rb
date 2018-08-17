#Break fixed-nonce CTR mode using statistics. essentially like set1/6.rb breaking repeating key xor
# by 'mistake' i implemented this when trying to do challenge 19 (break fixed nonce CTR with substitutions) (it's so much more intuitive)
require 'openssl'
require File.dirname(__FILE__ )+"/ctr.rb"

module CTR_break_stat
  $unencrypted = []
  def self.readfile
    f = File.readlines(File.dirname(__FILE__)+"/ctr_break_fixed_stat.txt")
    puts f[0].unpack('m').join
    (0...f.size).each do |i|
      $unencrypted[i] = f[i].unpack('m').join
      f[i] = CTR.ctr(f[i].unpack('m').join,'ABCDEFGHIJKLZZZZ',0x42.chr*16)
    end
    return f
  end
$longest = 40
  def self.analyse(f) #f array of ciphers encrypted under the same nonce in CTR mode
    num = f.size
    max_char = 0
    max_match = 0
    match_ctr = 0
    xor_stream = ''
    (0...$longest).each do |stream_pos|
      (0...256).each do |char|
        (0...num).each do |pos|
          str = f[pos]
          c = str[stream_pos]
          begin
          if (c.ord ^ char).chr.to_str.match?(/[ETAOIN SHRDLU]/i)
            match_ctr+=1
          end
          rescue NoMethodError #guess i dont even have to think about out of bounds anymore :P
            next
          end
        end
        if match_ctr > max_match #which char got the closest to english alphabet statistics?
          max_match = match_ctr
          max_char = char
        end
        match_ctr = 0 # reset the hit counter for the next char
      end
      xor_stream << max_char.chr
      max_char = 0
      max_match = 0
    end
    return xor_stream
  end
  def self.run
  f = readfile
  str = analyse(f)
  (0...f.size).each do |cipher_index|
    puts "\n--->actual\n"
    puts $unencrypted[cipher_index]
    puts "broken<---\n"
    (0..f[cipher_index].size).step($longest) do |block|
      begin
      (0...$longest).each do |ind|
        putc((f[cipher_index][block+ind].ord^str[ind].ord).chr)
      end
      rescue NoMethodError
        next
      end
    end
    puts""
  end
  puts "\nfair enough i think"
  end
end

    #CTR_break_stat.run


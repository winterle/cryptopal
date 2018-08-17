def xorchar(plain,char)

  result = []
  plain.scan(/../).map do |val|
    #val.to_i(16) convert hex to integer ; char.ord : int representation of character, .chr to character
    result.push((val.to_i(16)^char.ord).chr)
  end
  return result.join
end



def check_valid(plain)
maxcnt = 0
maxchar = 'a'

(0..255).each do |x|
  res = xorchar(plain,x.chr)
  #analysis for common characters
  cnt = res.scan(/[ETAOIN SHRDLU]/i).size #/i to ignore capital/non-capital
  if cnt > maxcnt
    maxcnt = cnt
    maxchar = x.chr
  end
end
#best match
if maxcnt > 15
  puts"--good bet: maxcnt = #{maxcnt}"
  puts(xorchar(plain,maxchar))
end

end


f = File.read("#{File.dirname(__FILE__ )}/4.dat")
(0..f.size/61).each do |line|
  cont = f[line*60,60]
  check_valid(cont)
end
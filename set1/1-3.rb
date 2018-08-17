
#testvars
hexstr = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
base64str=''
hexstr1 = '1c0111001f010100061a024b53535009181c'
hexstr2 = '686974207468652062756c6c277320657965'

def ishexencoded(hexstr)
  #sainiy checks
  if !hexstr.ascii_only?
    return false
  end

  bytes = hexstr.bytes.to_a
  for i in 0..bytes.size-1 do
    if bytes[i] > 47 and bytes[i] <= 9+48
    elsif bytes[i] > 96 and bytes[i] <= 5+97
    else
      return false
    end
  end
  return true
end

def hexto64(hexstr)
  if !ishexencoded(hexstr)
    puts('not hex encoded')
    exit(-1)
  end

  base64str=[[hexstr].pack("H*")].pack("m0")
  return base64str
end

def xorstr(hexstr1, hexstr2)
  if hexstr1.size != hexstr2.size
    puts('not equal sized hexstr strings')
    exit(-1)
  end
  a = hexstr1.to_i(16) #passed value is base
  b = hexstr2.to_i(16)

  result = a^b
  return result.to_s(16)

end

def xorchar(plain,char)

  result = []
  plain.scan(/../).map do |val|
    #val.to_i(16) convert hex to integer ; char.ord : int representation of character, .chr to character
    result.push((val.to_i(16)^char.ord).chr)
  end
  return result.join
end

plain = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
(0..255).each do |x|
  res = xorchar(plain,x.chr)
  #analysis for common characters
  cnt = res.scan(/[ETAOIN SHRDLU]/i).size #/i to ignore capital/non-capital
  if cnt > 19
    puts"--potential match, cnt = #{cnt}--"
    puts(res)
  end

end
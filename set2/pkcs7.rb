
module Pkcs7
def Pkcs7.pad(str,block_len)
  len = str.size
  pad_len = block_len - ( len % block_len)
  #puts "pkcs7: appending (dec) #{pad_len}"
  if pad_len
    (0...pad_len).each do
      str = str+pad_len.chr
    end
  end
  return str
end
end
require'openssl'
f = File.read("#{File.dirname(__FILE__ )}/8.dat")
#just leave it hex encoded

ciphers = f.scan(/\n/).size
puts"ciphers: #{ciphers}"

f.gsub!(/[\r\n\t]/,'')

stack = []
(0..f.size).step(32) do |block| #32*4 = 128 is size of AES-CBC block
  if block % (32*10) == 0
    stack.clear
  end
  bl = f[block,32]
  if stack.include?(bl)
    puts"found dup in block #{block}, which is cipher #{block/32/10}" #10 blocks per cipher
    puts(bl)
  else
    stack.push(bl)
  end
end

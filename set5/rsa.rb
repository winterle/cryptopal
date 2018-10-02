require 'openssl'

class RSA
    def keygen
        @p = OpenSSL::BN::generate_prime(456).to_i
        @q = OpenSSL::BN::generate_prime(456).to_i
        @n = @p*@q
        @et = (@p-1)*(@q-1)
        @e = 3
        @d = invmod(@e,@et)
    end

    def get_pub
        if @n.nil?
            raise 'call keygen first'
        end
        return [@e,@n]
    end

    def encrypt(string)
        if @e.nil?
            raise 'call keygen first'
        end
        cipher = modexp(string.unpack('H*').join('').to_i(16),@e,@n)
    end

    def decrypt(int)
        if @d.nil?
            raise 'call keygen first'
        end
        plain = modexp(int,@d,@n)
        return int_to_str(plain)
    end
end



def modexp(base,exp,mod)
    return 0 if mod == 1
    res = 1
    base = base%mod
    while exp > 0
        if exp%2==1
            res = (res * base)%mod
        end
        exp = exp >>1
        base = (base*base)%mod
    end
    return res
end

def int_to_str(int)
    str = ''
    while int > 0
        str << (int & 0xFF)
        int = int >> 8
    end
    return str.reverse!
end
def invmod(e, et)
    g, x = extended_gcd(e, et)
    if g != 1
        raise 'The maths are broken!'
    end
    x % et
end
def extended_gcd(a, b)
    if a<0 || b<0
        raise 'nope'
    end
    last_remainder, remainder = a, b
    x, last_x, y, last_y = 0, 1, 1, 0
    while remainder != 0
        last_remainder, (quotient, remainder) = remainder, last_remainder.divmod(remainder)
        x, last_x = last_x - quotient*x, x
        y, last_y = last_y - quotient*y, y
    end

    return last_remainder, last_x * (a < 0 ? -1 : 1)
    end
def nthroot(n, a, precision = 1e-1024)
    x = a #Official implementation casts to a float here.
    begin
        prev = x
        x = ((n - 1) * prev + a / (prev ** (n - 1))) / n
    end while (prev - x).abs > precision
    x
end
def run_broadcast
    x = RSA.new
    cipher = []
    keys=[]
    (0...3).each do
        x.keygen
        keys.push(x.get_pub[1])
        cipher.push(x.encrypt('verysecretstring'))
    end
    res = ((cipher[0]*(ms0 = (keys[1]*keys[2])) * invmod(ms0,keys[0])) +
         (cipher[1]*(ms1 = (keys[0]*keys[2])) * invmod(ms1,keys[1])) +
        (cipher[2]*(ms2 = (keys[0]*keys[1])) * invmod(ms2,keys[2])) ) % (keys[0] * keys[1] * keys[2])
    res = nthroot(3,res.to_i)
    puts int_to_str(res)
end
#uncomment to run
#run_broadcast


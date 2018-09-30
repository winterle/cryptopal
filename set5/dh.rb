require 'securerandom'
require 'openssl'
class DH
    def initialize(p,g)
        @pmod = p
        @gen = g
    end

    def gen_priv
        @priv = SecureRandom.random_bytes(32)
        @priv = @priv.unpack('H*').join('').to_i(16)%@pmod
    end

    def gen_pub
        if @priv.nil?
            raise "generate private key first"
        end
        @pub = modexp(@gen,@priv,@pmod)
    end

    def modexp(base,exp,mod)
        return 0 if mod == 1
        res =1
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
    def gen_s
        if @priv.nil? || @pub_other.nil?
            raise "parameters not set"
        end
        @session = modexp(@pub_other,@priv,@pmod)
        sha1 = OpenSSL::Digest::SHA1.new
        sha1 << @session.to_s
        @aes_key = sha1.digest
    end
    def set_pub_other(new)
        @pub_other = new
    end
    def set_params(g,p)
        @gen = g
        @pmod = p
    end
    def get_g
        @gen
    end
    def get_p
        @pmod
    end
    def get_pub
        @pub
    end
    def aes_cbc(msg)
        if @session.nil?
            gen_s
        end
        iv = OpenSSL::Random.random_bytes(16)
        enc = OpenSSL::Cipher.new('AES-128-CBC')
        enc.encrypt
        enc.key = @aes_key[0,16]
        enc.iv=iv
        cipher = enc.update(msg)+enc.final+iv
    end
    def aes_cbc_dec(cipher)
        if @session.nil?
            gen_s
        end
        iv = cipher[16,16]
        dec = OpenSSL::Cipher.new('AES-128-CBC')
        dec.decrypt
        dec.key =@aes_key[0,16]
        dec.iv=iv
        plain = dec.update(cipher[0,16])+dec.final
    end
    def echo_msg(cipher)
        plain = aes_cbc_dec(cipher)
        ret = aes_cbc(plain)
    end

    #for the MITM
    def set_session(new)
        @session = new
        sha1 = OpenSSL::Digest::SHA1.new
        sha1 << @session.to_s
        @aes_key = sha1.digest
    end
end


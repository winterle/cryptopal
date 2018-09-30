require 'securerandom'
require 'openssl'
class SRP_client


    def initialize
        #static parameters
        @prime = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
                  e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
                  3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
                  6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
                  24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
                  c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
                  bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
                  fffffffffffff".to_i(16)
        @gen = 2
        @k = 3
        @mail = "email@provider.com"
        @pass = "password"
        #private key
        @priv = SecureRandom.random_bytes(32).unpack('H*').join('').to_i(16)
        #public key
        @pub = modexp(@gen,@priv,@prime)
    end
    def send_pub
        [@mail,@pub]
    end
    def receive_pub(packet)
        if packet.class != Array || packet.length != 2
            raise "faulty packet received"
        end
        @salt = packet[0]
        @pub_other = packet[1]
        sha256 = OpenSSL::Digest.new('sha256')
        sha256 << (@pub.to_s+@pub_other.to_s)
        @uH = sha256.hexdigest.to_i(16)
        sha256.reset
        sha256 << (@salt.to_s+@pass)
        @xH = sha256.hexdigest.to_i(16)
        @session = modexp(@pub_other - @k * modexp(@gen,@xH,@prime),(@priv + @uH * @xH),@prime)
        sha256.reset
        sha256 << @session.to_s
        @K_hash = sha256.hexdigest.to_i(16)
    end
    def send_proof
        sha256 = OpenSSL::Digest.new('sha256')
        hmac = OpenSSL::HMAC.hexdigest(sha256,@K_hash.to_s,@salt.to_s).to_i(16)
    end

end
class SRP_server
    def initialize
        #static parameters
        @prime = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
                  e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
                  3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
                  6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
                  24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
                  c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
                  bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
                  fffffffffffff".to_i(16)
        @gen = 2
        @k = 3
        @mail = "email@provider.com"
        @pass = "password"

        #private key
        @priv = SecureRandom.random_bytes(32).unpack('H*').join('').to_i(16)

        # generate password verifier, save salt and verifier
        @salt = SecureRandom.random_bytes(32).unpack('H*').join('').to_i(16)
        sha256 = OpenSSL::Digest.new('SHA256')
        sha256 << (@salt.to_s + @pass)
        xH = sha256.hexdigest.to_i(16)
        #password verifier
        @v = modexp(@gen,xH,@prime)

        #public key (abit different than DH)
        @pub = (@k*@v+modexp(@gen,@priv,@prime))%@prime
    end
    def receive_pub(packet)
        if packet.class != Array || packet.length != 2
            raise "faulty packet received"
        end
        @mail_received = packet[0]
        @pub_other = packet[1]
        sha256 = OpenSSL::Digest.new('sha256')
        sha256 << (@pub_other.to_s+@pub.to_s)
        @uH = sha256.hexdigest.to_i(16)
        #calculate session key in mod prime field
        @session = modexp(@pub_other*modexp(@v,@uH,@prime),@priv,@prime)
        sha256.reset
        sha256 << @session.to_s
        @K_hash = sha256.hexdigest.to_i(16)
    end
    def send_pub
        [@salt,@pub]
    end
    def receive_proof(packet)
        if packet.class != Integer
            raise "faulty packet received"
        end
        sha256 = OpenSSL::Digest.new('sha256')
        hmac = OpenSSL::HMAC.hexdigest(sha256,@K_hash.to_s,@salt.to_s).to_i(16)
        if hmac != packet
            raise "fatal: hmac validation failed"
        end
        puts "hmac validation successful"
    end
end

class SRP_hax0r < SRP_client
    #override initialize so we dont know the password
    def initialize
        #static parameters
        @prime = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
                  e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
                  3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
                  6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
                  24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
                  c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
                  bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
                  fffffffffffff".to_i(16)
        @gen = 2
        @k = 3
        @mail = "email@provider.com"
        @pass = "not the correct password"
        #private key
        @priv = SecureRandom.random_bytes(32).unpack('H*').join('').to_i(16)
        #public key
        @pub = modexp(@gen,@priv,@prime)
    end
    #override the send public key function to send 0 instead of actual public key
    # alter the send public key: try 0 ; @prime*n where n is >= 0
    # now, the server calculates: @session = modexp(0*modexp(@v,@uH,@prime),@priv,@prime) = modexp(0,@priv,@prime) = 0
    # or                          @session = modexp((@prime*n) * modexp(@v,@uH,@prime),@priv,@prime) = modexp(0,@priv,@prime) = 0
    # (congruent to the first calculation since in mod prime field)
    def send_pub
        [@mail,@prime*7]
    end
    def set_session(value,salt)
        @session = value
        sha256 = OpenSSL::Digest.new('sha256')
        sha256 << @session.to_s
        @K_hash = sha256.hexdigest.to_i(16)
        @salt = salt
    end
    def get_prim
        @prime
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

print "normal execution\n"
srv = SRP_server.new
cli = SRP_client.new
msg = cli.send_pub
srv.receive_pub(msg)
msg = srv.send_pub
cli.receive_pub(msg)
msg = cli.send_proof
srv.receive_proof(msg)

print "exploit\n"
srv = SRP_server.new
#does not know the password
hax0r = SRP_hax0r.new
msg = hax0r.send_pub
#malicious packet
srv.receive_pub(msg)
msg = srv.send_pub
#we just need the salt, session key will be 0 and public key doesnt matter
hax0r.set_session(0,msg[0])
msg = hax0r.send_proof
srv.receive_proof(msg)




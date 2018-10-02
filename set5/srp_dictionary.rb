require 'securerandom'
require 'openssl'
class SRP_simple_client


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
        @pass = "Welcome"
        #private key
        @priv = SecureRandom.random_bytes(32).unpack('H*').join('').to_i(16)
        #public key
        @pub = modexp(@gen,@priv,@prime)
    end
    def send_pub
        [@mail,@pub]
    end
    def receive_pub(packet)
        if packet.class != Array || packet.length != 3
            raise "faulty packet received"
        end
        @salt = packet[0]
        @pub_other = packet[1]
        @u = packet[2]
        sha256 = OpenSSL::Digest.new('sha256')
        sha256 << (@salt.to_s+@pass)
        @x = sha256.hexdigest.to_i(16)
        @session = modexp(@pub_other, (@priv + @u * @x),@prime)
        sha256.reset
        sha256 << @session.to_s
        @K_hash = sha256.hexdigest.to_i(16)
    end
    def send_proof
        sha256 = OpenSSL::Digest.new('sha256')
        hmac = OpenSSL::HMAC.hexdigest(sha256,@K_hash.to_s,@salt.to_s).to_i(16)
    end

end
class SRP_simple_server
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
        @pass = "Welcome"

        @u = SecureRandom.random_bytes(16).unpack('H*').join('').to_i(16)
        #private key
        @priv = SecureRandom.random_bytes(32).unpack('H*').join('').to_i(16)

        # generate password verifier, save salt and verifier
        @salt = SecureRandom.random_bytes(32).unpack('H*').join('').to_i(16)
        sha256 = OpenSSL::Digest.new('SHA256')
        sha256 << (@salt.to_s + @pass)
        xH = sha256.hexdigest.to_i(16)
        #password verifier
        @v = modexp(@gen,xH,@prime)

        #public key
        @pub = modexp(@gen,@priv,@prime)
    end
    def receive_pub(packet)
        if packet.class != Array || packet.length != 2
            raise "faulty packet received"
        end
        @mail_received = packet[0]
        @pub_other = packet[1]
        sha256 = OpenSSL::Digest.new('sha256')
        #calculate session key in mod prime field
        @session = modexp(@pub_other*modexp(@v,@u,@prime),@priv,@prime)
        sha256 << @session.to_s
        @K_hash = sha256.hexdigest.to_i(16)
    end
    def send_pub
        [@salt,@pub,@u]
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

class SRP_simple_hax0r < SRP_simple_server
    #override initialize
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
        #private key
        @priv = SecureRandom.random_bytes(32).unpack('H*').join('').to_i(16)
        #public key
        @pub = modexp(@gen,@priv,@prime)
        @salt = SecureRandom.random_bytes(32).unpack('H*').join('').to_i(16)
        @u = SecureRandom.random_bytes(16).unpack('H*').join('').to_i(16)
    end

    def send_pub
        #[salt,pubkey,u]
        [@salt,@pub,@u]
    end
    def receive_proof(msg)
        sha256 = OpenSSL::Digest.new('SHA256')
        #set this to file, e.g. /usr/dict/words
        # lets put some strain on the cpu :)
        capitalize = false
        done = false
        (0...2).each do |a|

        File.open("/usr/share/dict/words", "r") do |f|
                if done
                    break
                end
                if a == 1
                    capitalize = true
                end
                f.each_line do |password|
                    if capitalize
                        password[0] = password[0].upcase
                    end
                    password = password[0,password.length-1] #remove trailing \n
                    sha256 << (@salt.to_s + password)
                    x = sha256.hexdigest.to_i(16)
                    #password verifier
                    v = modexp(@gen,x,@prime)
                    sha256.reset
                    @session = modexp(@pub_other*modexp(v,@u,@prime),@priv,@prime)
                    sha256 << @session.to_s
                    @K_hash = sha256.hexdigest.to_i(16)
                    sha256.reset
                    hmac_hex = OpenSSL::HMAC.hexdigest(sha256,@K_hash.to_s,@salt.to_s)
                    hmac = hmac_hex.to_i(16)
                    print hmac_hex+" --- #{password}#{' '*30}\r"
                    sha256.reset
                    if hmac == msg
                        puts "password found: '#{password}'#{' '*70}\n"
                        done = true
                        break
                    end
                end
            end
        end
    end
    def receive_pub(packet)
        if packet.class != Array || packet.length != 2
            raise "faulty packet received"
        end
        @mail_received = packet[0]
        @pub_other = packet[1]
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
srv = SRP_simple_server.new
cli = SRP_simple_client.new
msg = cli.send_pub
srv.receive_pub(msg)
msg = srv.send_pub
cli.receive_pub(msg)
msg = cli.send_proof
srv.receive_proof(msg)

print "dict attack, posing as server\n"
hax0r_srv = SRP_simple_hax0r.new
cli = SRP_simple_client.new
msg = cli.send_pub
hax0r_srv.receive_pub(msg)
msg = hax0r_srv.send_pub
cli.receive_pub(msg)
msg = cli.send_proof
hax0r_srv.receive_proof(msg)


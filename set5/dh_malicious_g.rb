require_relative 'dh'
g = 2
p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff".to_i(16)

#MITM with bad g:
#initialize the client
dh_cli = DH.new(p,g)
dh_cli.gen_priv
dh_cli.gen_pub
#send params to echo bot, init bot
# alter g: try g = 1; g = p; g = p-1
g = p-1
dh_mitm = DH.new(p,g)
dh_mitm.gen_priv

dh_echo = DH.new(p,g)
dh_echo.set_pub_other(dh_cli.get_pub)
dh_echo.gen_priv
dh_echo.gen_pub
dh_cli.set_pub_other(dh_echo.get_pub)
#all parties calculate the session key and derive the aes-cbc key
dh_echo.gen_s
dh_cli.gen_s
#now, mitm can read all messages since
cipher = dh_cli.aes_cbc("very secret")
if g == 1
    #since g = 1 , the echo-bot's public key will be: (1**priv)%p = 1, so the clients session key will be (1**priv)%p = 1
    # (mitm would have to de-and reencrypt to relay messages)
    dh_mitm.set_pub_other(1)
    dh_mitm.gen_s
    print "mitm read:\n"
    puts dh_mitm.aes_cbc_dec(cipher)
    # if the bot tries to decrypt, it'll be bananas
    print "bot's decrypt (bananas):\n"
    begin
    puts dh_echo.aes_cbc_dec(cipher)
    rescue StandardError => e
        puts e
    end
end
if g == p
    #since g = p, the echo-bot's public key will be: (p**priv)%p = p, so the clients session key will be (p**priv)%p = p
    dh_mitm.set_pub_other(p)
    dh_mitm.gen_s
    print "mitm read:\n"
    puts dh_mitm.aes_cbc_dec(cipher)
end
if g == p-1
    # since g = p-1, the echo-bot's public key will be: ((p-1)**priv)%p = p-1 || 1 , so the clients session key will be ((p-1 || 1)**priv)%p = p-1 || 1 (where || is either or)
    # fixme sometimes bad decrypt
    dh_mitm.set_session(p-1)
    print "mitm read:\n"
    begin
    puts dh_mitm.aes_cbc_dec(cipher)

    rescue StandardError => e
        dh_mitm.set_session(1)
        puts dh_mitm.aes_cbc_dec(cipher)
    end
end


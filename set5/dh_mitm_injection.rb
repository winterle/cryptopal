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
#initialize the client
dh_cli = DH.new(p,g)
dh_cli.gen_priv
dh_cli.gen_pub
#send params to echo bot, init bot
cli_pub = dh_cli.get_pub
dh_echo = DH.new(p,g)
dh_echo.set_pub_other(cli_pub)
dh_echo.gen_priv
dh_echo.gen_pub
#send bot's public key to client
dh_cli.set_pub_other(dh_echo.get_pub)
#both parties calculate the session key
dh_echo.gen_s
dh_cli.gen_s
#client sends message to echo, echo sends it back and client can decrypt it
cipher = dh_cli.aes_cbc("echo me")
dh_echo.echo_msg(cipher)
puts dh_cli.aes_cbc_dec(cipher)

#now to the MITM with parameter injection: by swapping out the public keys with p, calculation of @session key is doomed: @session = p^priv%p = 0
#initialize the client
dh_cli = DH.new(p,g)
dh_cli.gen_priv
dh_cli.gen_pub
#send params to echo bot, init bot
dh_echo = DH.new(p,g)
dh_mitm = DH.new(p,g)
dh_mitm.set_pub_other(p)
dh_mitm.gen_priv
# inject
dh_echo.set_pub_other(p)
dh_echo.gen_priv
dh_echo.gen_pub
# inject
dh_cli.set_pub_other(p)
#all parties calculate the session key (which is now 0) and derive the aes-cbc key
dh_echo.gen_s
dh_cli.gen_s
dh_mitm.gen_s
#now, mitm can read all messages
cipher = dh_cli.aes_cbc("very secret")
print "mitm read:\n"
puts dh_mitm.aes_cbc_dec(cipher)


#to run this 'server', gem sinatra is required
# warning: this server is pretty much useless for anything except returning the corresponding status codes iff receiving CORRECT queries

require 'sinatra'
require 'openssl'


# static during runtime, assume this key is exchanged using some protocol
$key = OpenSSL::Random.random_bytes(32)


get '/test' do
    # matches "GET /test?file=foo&signature=bar"
    file = params[:file]
    sig = params[:signature]
    # calculate the hmac for file

    hmac = OpenSSL::HMAC.hexdigest('sha1',$key,file)
    if !insecure_compare(sig,hmac)
        status 500
        "500 wrong signature"
    else
        status 200
        "signature OK;
        file = #{file};
        signature = #{sig}"
    end

end

def compare(hex1,hex2)
    if hex1 == hex2
        return true
    end
    return false
end

def insecure_compare(hex1,hex2)
    #compare byte by byte with early exit
    hex1 = [hex1].pack('H*')
    hex2 = [hex2].pack('H*')
    time = 0.0

    if hex1.length != hex2.length
        return false
    end
    (0...hex1.length).each do |i|
        if !(hex1[i].eql?(hex2[i]))
            sleep(time)
            return false
        end
        # kind of a cheat here, but calling sleep close to 20 times (digest length) for each byte makes measuring execution time remotely
        # really unpredictable (practically yield), calling it once is fine
        time+=0.005 # 5 milliseconds
    end
    sleep(time)
    return true
end
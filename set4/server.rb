#to run this 'server', gem sinatra is required
# warning: this server is pretty much useless for anything except returning the corresponding status codes iff receiving CORRECT queries

require 'sinatra'
require 'openssl'


# static during runtime, assume this key is exchanged using some protocol
$key = 'A'*16#OpenSSL::Random.random_bytes(32)


get '/test' do
    # matches "GET /test?file=foo&signature=bar"
    file = params[:file]
    sig = params[:signature]
    # calculate the hmac for file

    hmac = OpenSSL::HMAC.hexdigest('sha1',$key,file)
    puts hmac
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

    if hex1.length != hex2.length
        return false
    end
    (0...hex1.length).each do |i|
        if hex1[i] != hex2[i]
            return false
        end
        sleep(0.02)
    end
    return true
end
require 'net/http'
require 'open-uri'
module Timing

    url_stub = URI.parse("http://127.0.0.1/test?file=testfile&signature=80b662265c03454ec90a8e40599c6a01b768dff9")
    # puma listening on port 4567
    # sinatra has some pretty interesting lag spikes, this has become rather complex
    def self.exploit(filename)
        uri_stub = "http://127.0.0.1/test?"
        done = false
        byte = 0
        digest_len = 20
        timeout_len = 0.02 #s
        #start persistent connection
        url = URI(uri_stub + "file=#{filename}&signature=stub")
        Net::HTTP.start(url.host,4567) do |http|
            sig_known = ""
            while !done
                #forge new request
                hex_byte = byte.to_s(16)

                #prepend leading 0
                hex_byte = "0"<<hex_byte if hex_byte.length==1

                #fill up to digest_length
                fill = digest_len*2-(sig_known.length+2)

                url = URI(uri_stub + "file=#{filename}&signature=#{sig_known}#{hex_byte}#{'0'*fill}")

                #measure execution time
                time_start = Time.now
                request = Net::HTTP::Get.new url
                ret = http.request request
                time_end = Time.now
                time_total = time_end - time_start
                puts "query: file=#{filename}&signature=#{sig_known}#{hex_byte}#{'0'*fill}"
                #puts "response time: #{time_total}"

                #increment byte
                if byte == 0xFF
                    raise "failed, correct byte could not be found"
                end
                if (len = time_total-((sig_known.length/2) * timeout_len)) > timeout_len
                    if len > timeout_len * 1.5
                        #puts "Unexpected Latency Hit, reset"
                        next
                    else #try this byte a few times to be absolutely sure it produces the correct timeout, take arithmetic mean
                        mean = 0
                        #validate an increasing amount of times
                        retrys = (sig_known.length/4)+2
                        valid = true
                        (0...retrys).each do |i|
                            time_start = Time.now
                            request = Net::HTTP::Get.new url
                            ret = http.request request
                            time_end = Time.now
                            time_total = time_end - time_start
                            len = time_total-((sig_known.length/2) * timeout_len)
                            # this measurement is pretty off
                            if len > timeout_len*1.5
                                redo
                            end
                            # this byte produced no timeout in this try, cannot be the one
                            if len < timeout_len
                                valid = false
                                break
                            end
                            mean += len
                        end
                        mean/=retrys
                        if !(mean > timeout_len) || !valid
                            byte+=1
                            next
                        end
                    end
                    #found correct byte
                    sig_known<<hex_byte
                    byte = 0
                end
                # we're done
                if sig_known.length == digest_len*2
                    done = true
                    puts "found signature: #{sig_known}"
                    puts "status code: HTTP #{ret.code} #{ret.message}"
                    puts ret.body
                end
                byte+=1
            end
        end
    end



    self.exploit("testfile")

end
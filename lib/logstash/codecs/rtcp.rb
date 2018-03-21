require "logstash/codecs/base"
require "logstash/namespace"
require "rtcp"

class LogStash::Codecs::Rtcp < LogStash::Codecs::Base

  # The codec name
  config_name "rtcp"

  # Append a string to the message
  config :tag_on_failure, :validate => :boolean, :default => false

  public
  def register
  end # def register

  public
  def decode(data)
     rtcp_decode_array = RTCP.decode_all(data)
     rtcp_parsed_data = []
     rtcp_decode_array.each { |rtcp_decode|
        rtcp_decode_hash = {}
        rtcp_decode_hash = rtcp_decode.instance_variables.each_with_object({}){|var, hash| hash[var.to_s.delete("@")] = rtcp_decode.instance_variable_get(var)}
        rtcp_decode_hash["class"] = rtcp_decode.class.name
        rtcp_decode_hash.delete("packet_data")
        rtcp_parsed_data.push(rtcp_decode_hash)
     }
     yield LogStash::Event.new({"rtcp_data" => rtcp_parsed_data})
  rescue => e
    if tag_on_failure
      @logger.error("RTCP parse error, original data now in message field", :error => e)
      yield LogStash::Event.new("message" => data, "tags" => ["_rtcpparsefailure"])
    else
      raise e
    end
  end # def decode


end # class LogStash::Codecs::Rtcp

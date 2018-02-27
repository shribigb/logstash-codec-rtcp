# encoding: utf-8
require_relative '../spec_helper'
require "logstash/codecs/rtcp"

describe LogStash::Codecs::Rtcp do

  context "#decode with tag_on_failure" do
      let (:rtcp_config) {super.merge("tag_on_failure" => true)}

      it "should tag event on failure" do
        subject.decode("not rtcp") do |event|
          insist {event.is_a? LogStash::Event}
          insist {event.get("tags")} == ["_rtcpparsefailure"]
        end
      end
    end	
end

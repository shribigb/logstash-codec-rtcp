# The MIT License (MIT)

# Copyright © 2013 Christian Rusch

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# BYE: Goodbye RTCP Packet
# Documentation: RFC 3550, 6.6
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |V=2|P|    SC   |   PT=BYE=203  |             length            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                           SSRC/CSRC                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       :                              ...                              :
#       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# (opt) |     length    |               reason for leaving            ...
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class RTCP::BYE < RTCP

  PT_ID = 203

  attr_reader :version, :ssrcs, :reason, :padding

  def decode(packet_data)
    vpsc, packet_type, length = packet_data.unpack('CCn')
    ensure_packet_type(packet_type)

    @length  = 4 * (length + 1)
    @version = vpsc >> 6
    count    = vpsc & 15

    bye_data = payload_data(packet_data, @length, 4)

    @ssrcs = bye_data.unpack("N#{count}")

    if (4 * count) < bye_data.length
      rlen, data = bye_data.unpack("x#{4 * count}Ca*")
      @reason = data[0..(rlen - 1)]

      # If the string fills the packet to the next 32-bit boundary,
      # the string is not null terminated.  If not, the BYE packet
      # MUST be padded with null octets to the next 32- bit boundary.
      # $TODO: Remove padding?

      # $TODO: Check for/extract packet padding
    end
    self
  end

end

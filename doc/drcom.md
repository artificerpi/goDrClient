# drcom protocol

## Packet
- Decode
drcom packet (payload bytes of udp)

- Solve too many replicate packets problem:
Based on the packet analysis using wireshark, the sequence of drcom packet 
should be in order. But somethimes there is a problem that many replicate 
packets are sent by server. So I use a `lastMsgType` value to record and 
ignore latter ones.
# PacketLib.jl

Julia library for crafting and capturing packets, with a focus on flexibility and expressiveness. Work with a wide range of protocols, or use it to develop a new one.

**This library is still under development, and should not be used in production until verified on all platforms under a range of conditions. (~V.6) Use on platforms other than Darwin has not been conducted. **

Any contributions are welcome, but those necessary for the next release are preferable.

___

### Roadmap

_Version 1_

- [x] ethernet packet crafting
- [x] ethernet packet sending
- [x] darwin support (bpf)

_Version 2_

- [ ] ethernet packet capturing
- [ ] 802.3 (capture/crafting)

_Version 3_

- [ ] IPv4 (capture/crafting)
- [ ] IPv6 (capture/crafting)

_Version 4_

- [ ] UDP (capture/crafting)
- [ ] TCP (capture/crafting)

_Version 4_

- [ ] ARP (capture/crafting)
- [ ] TCP (capture/crafting)

_Version 5_

- [ ] packet (protocol) creation framework

_Version 6_
- [ ] windows support (npcap?)
- [ ] linux support (libpcap?)

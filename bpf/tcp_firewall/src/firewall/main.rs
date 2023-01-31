#![no_std]
#![no_main]
use cty::*;
use redbpf_probes::maps::HashMap;
use redbpf_probes::xdp::prelude::*;
use tcp_firewall::firewall::SYN;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/WHITE_LIST")]
pub static mut WHITE_LIST: HashMap<__be32, ()> = HashMap::with_max_entries(1000);

#[xdp("firewall")]
pub fn firewall(ctx: XdpContext) -> XdpResult {
    // only process TCP packets
    let tcp = match ctx.transport()? {
        t @ Transport::TCP(_) => t,
        _ => return Ok(XdpAction::Pass),
    };
    // we only process SYN packets, all other packets can go through
    if !has_flag(&tcp, SYN) {
        return Ok(XdpAction::Pass);
    }
    // target is not our tcp server
    if tcp.dest() != 5051 {
        return Ok(XdpAction::Pass);
    }
    let ip = unsafe { *ctx.ip()? };

    if let None = unsafe { WHITE_LIST.get(&ip.saddr) } {
        unsafe { WHITE_LIST.set(&ip.saddr, &()) };
        Ok(XdpAction::Pass)
        // Ok(XdpAction::Drop)
    } else {
        Ok(XdpAction::Pass)
    }
}

#[inline]
fn has_flag(tcp: &Transport, flag: u16) -> bool {
    if let Transport::TCP(hdr) = tcp {
        let flags = unsafe { *(&(**hdr)._bitfield_1 as *const _ as *const u16) };
        return flags & flag != 0;
    }

    return false;
}

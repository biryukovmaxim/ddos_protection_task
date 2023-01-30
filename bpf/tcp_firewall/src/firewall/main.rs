#![no_std]
#![no_main]
use cty::*;

use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[xdp("firewall")]
pub fn firewall(ctx: XdpContext) -> XdpResult {
    if let Ok(transport) = ctx.transport() {
        if transport.source().rem_euclid(2) == 0 && transport.dest() == 5051 {
            return Ok(XdpAction::Drop);
        }
    }

    Ok(XdpAction::Pass)
}
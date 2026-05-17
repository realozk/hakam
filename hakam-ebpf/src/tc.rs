use aya_ebpf::{maps::lpm_trie::Key, programs::TcContext};
use network_types::eth::EthHdr;

use crate::{helpers::increment_drop_counter, BLOCKLIST, TC_ACT_OK, TC_ACT_SHOT};

pub fn run(ctx: TcContext) -> i32 {
    match try_egress(&ctx) {
        Ok(v) => v,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
fn try_egress(ctx: &TcContext) -> Result<i32, ()> {
    let ether_type: u16 = ctx.load(12).map_err(|_| ())?;
    if ether_type != 0x0800_u16.to_be() {
        return Ok(TC_ACT_OK);
    }

    let dst_addr: u32 = ctx.load(EthHdr::LEN + 16).map_err(|_| ())?;

    if BLOCKLIST.get(&Key::new(32u32, dst_addr)).is_some() {
        increment_drop_counter();
        return Ok(TC_ACT_SHOT);
    }

    Ok(TC_ACT_OK)
}

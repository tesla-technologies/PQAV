// SPDX-License-Identifier: MIT OR Apache-2.0
use pqav::ts::{parse_packet, parse_pat, parse_pmt, SectionAssembler, PAT_PID, TS};
use std::collections::BTreeMap;

#[test]
#[ignore = "necesita testdata/entrada.ts"]
fn m1_tablas_de_entrada() {
    let datos = std::fs::read("testdata/entrada.ts").expect("falta testdata/entrada.ts");
    assert_eq!(datos.len() % TS, 0);
    let mut por_pid: BTreeMap<u16, u64> = BTreeMap::new();
    let mut pat = SectionAssembler::new();
    let mut pmt = SectionAssembler::new();
    let mut pmt_pid = None;
    let mut impresa = false;
    for p in datos.chunks_exact(TS) {
        let pkt = parse_packet(p).unwrap();
        *por_pid.entry(pkt.pid).or_default() += 1;
        if pkt.pid == PAT_PID {
            if let Some(s) = pat.push(&pkt) {
                pmt_pid = Some(parse_pat(&s).unwrap());
            }
        } else if Some(pkt.pid) == pmt_pid && !impresa {
            if let Some(s) = pmt.push(&pkt) {
                println!("{:?}", parse_pmt(&s).unwrap());
                impresa = true;
            }
        }
    }
    for (pid, n) in &por_pid {
        println!("0x{pid:04X} {n}");
    }
}

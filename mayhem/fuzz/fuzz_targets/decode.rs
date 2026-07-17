// Fuzz ethabi::decode over an arbitrary (Vec<ParamType>, payload) pair, the same
// code path as the original fork's harness. The original derived Arbitrary for
// ParamType by patching upstream; this harness stays purely additive by building
// ParamType values locally from the fuzz input instead.
#![no_main]
use arbitrary::Unstructured;
use ethabi::ParamType;
use libfuzzer_sys::fuzz_target;

fn arb_param_type(u: &mut Unstructured, depth: u32) -> arbitrary::Result<ParamType> {
    let max = if depth >= 3 { 7 } else { 10 };
    Ok(match u.int_in_range(0..=max)? {
        0 => ParamType::Address,
        1 => ParamType::Bytes,
        2 => ParamType::Int(8 * u.int_in_range(1..=32u32)? as usize),
        3 => ParamType::Uint(8 * u.int_in_range(1..=32u32)? as usize),
        4 => ParamType::Bool,
        5 => ParamType::String,
        6 => ParamType::FixedBytes(u.int_in_range(0..=64u32)? as usize),
        7 => ParamType::Address,
        8 => ParamType::Array(Box::new(arb_param_type(u, depth + 1)?)),
        9 => ParamType::FixedArray(Box::new(arb_param_type(u, depth + 1)?), u.int_in_range(0..=8u32)? as usize),
        _ => {
            let n = u.int_in_range(0..=4u32)?;
            let mut inner = Vec::new();
            for _ in 0..n {
                inner.push(arb_param_type(u, depth + 1)?);
            }
            ParamType::Tuple(inner)
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let n = u.int_in_range(0..=8u32).unwrap_or(0);
    let mut types = Vec::new();
    for _ in 0..n {
        match arb_param_type(&mut u, 0) {
            Ok(t) => types.push(t),
            Err(_) => break,
        }
    }
    let payload = u.take_rest();
    let _ = ethabi::decode(&types, payload);
});

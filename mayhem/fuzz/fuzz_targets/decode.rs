// Fuzz ethabi::decode over an arbitrary (Vec<ParamType>, payload) pair, reconstructing
// the mayhemheroes fork's harness (commit 53489fa3101e4a8bb2f37eb8b5e68c1219f31866),
// which fuzzed `fuzz_target!(|data: (Vec<ethabi::ParamType>, &[u8])| ...)` by patching
// upstream's `ParamType` with `#[derive(arbitrary::Arbitrary)]`.
//
// Patching upstream is off-limits here (BACKPORT.md: no edit to any upstream file), so
// this mirrors `ParamType`'s exact shape locally and derives `Arbitrary` on the mirror
// instead: the derive macro walks variants/fields in the same order, so it consumes the
// fuzz input identically to the original, and the original run's crashers replay as-is.
#![no_main]
use arbitrary::Arbitrary;
use ethabi::ParamType;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum ArbParamType {
    Address,
    Bytes,
    Int(usize),
    Uint(usize),
    Bool,
    String,
    Array(Box<ArbParamType>),
    FixedBytes(usize),
    FixedArray(Box<ArbParamType>, usize),
    Tuple(Vec<ArbParamType>),
}

impl From<ArbParamType> for ParamType {
    fn from(t: ArbParamType) -> ParamType {
        match t {
            ArbParamType::Address => ParamType::Address,
            ArbParamType::Bytes => ParamType::Bytes,
            ArbParamType::Int(n) => ParamType::Int(n),
            ArbParamType::Uint(n) => ParamType::Uint(n),
            ArbParamType::Bool => ParamType::Bool,
            ArbParamType::String => ParamType::String,
            ArbParamType::Array(inner) => ParamType::Array(Box::new((*inner).into())),
            ArbParamType::FixedBytes(n) => ParamType::FixedBytes(n),
            ArbParamType::FixedArray(inner, n) => ParamType::FixedArray(Box::new((*inner).into()), n),
            ArbParamType::Tuple(v) => ParamType::Tuple(v.into_iter().map(Into::into).collect()),
        }
    }
}

fuzz_target!(|data: (Vec<ArbParamType>, &[u8])| {
    let (types, payload) = data;
    let types: Vec<ParamType> = types.into_iter().map(Into::into).collect();
    let _ = ethabi::decode(&types, payload);
});

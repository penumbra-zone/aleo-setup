use std::convert::TryInto;

pub fn transform<A, B, const N: usize>(data: [A; N], f: impl Fn(A) -> B) -> [B; N] {
    match data.into_iter().map(f).collect::<Vec<B>>().try_into() {
        Ok(x) => x,
        _ => panic!("The size of the iterator should not have changed"),
    }
}

pub fn transform_parallel<A, B, const N: usize>(data: [A; N], f: impl Fn(A) -> B) -> [B; N] {
    transform(data, f)
}

pub fn flatten_results<A, E, const N: usize>(data: [Result<A, E>; N]) -> Result<[A; N], E> {
    let mut buf = Vec::with_capacity(N);
    for x in data {
        buf.push(x?);
    }
    match buf.try_into() {
        Ok(x) => Ok(x),
        _ => panic!("The size of the iterator should not have changed"),
    }
}

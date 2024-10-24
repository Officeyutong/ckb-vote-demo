use bnum::{cast::As, BUint};

pub fn mul_mod_expand<const S: usize, const S2: usize>(
    a: BUint<S>,
    b: BUint<S>,
    p: BUint<S>,
) -> BUint<S> {
    let c = (a.as_::<BUint<S2>>()) * (b.as_::<BUint<S2>>());
    let result = c % p.as_::<BUint<S2>>();
    result.as_()
}

pub fn add_mod_expand<const S: usize, const S2: usize>(
    a: BUint<S>,
    b: BUint<S>,
    p: BUint<S>,
) -> BUint<S> {
    let c = (a.as_::<BUint<S2>>()) + (b.as_::<BUint<S2>>());
    let result = c % p.as_::<BUint<S2>>();
    result.as_()
}

pub unsafe fn mul_mod<const S: usize>(a: BUint<S>, b: BUint<S>, p: BUint<S>) -> BUint<S> {
    let c: BUint<S> = (a).unchecked_mul(b);
    let result = c % p;
    result
}

pub fn power_mod<const S: usize, const S2: usize>(
    base: BUint<S>,
    mut index: u64,
    modular: BUint<S>,
) -> BUint<S> {
    let mut base: BUint<S2> = base.as_();
    let mut result = BUint::<S2>::ONE;
    let modular: BUint<S2> = modular.as_();

    while index != 0 {
        if (index & 1) == 1 {
            result = unsafe { mul_mod::<S2>(result, base, modular) };
        }
        base = unsafe { mul_mod::<S2>(base, base, modular) };
        index >>= 1;
    }
    result.as_()
}

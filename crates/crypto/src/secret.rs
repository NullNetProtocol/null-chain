//! Zeroizing, constant-time wrappers around field elements.
//!
//! `pasta_curves` types do not implement `Zeroize`. These newtypes implement
//! [`DefaultIsZeroes`], which gives a volatile zeroing write on drop and lets
//! the key types derive `Zeroize` and `ZeroizeOnDrop`.

use core::fmt;

use pasta_curves::pallas;
use subtle::{Choice, ConstantTimeEq};
use zeroize::DefaultIsZeroes;

/// Placeholder printed instead of secret material.
const REDACTED: &str = "<redacted>";

macro_rules! secret_field {
    ($(#[$doc:meta])* $name:ident, $inner:ty) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name($inner);

        impl DefaultIsZeroes for $name {}

        impl $name {
            /// Wraps a field element as secret material.
            pub fn new(inner: $inner) -> Self {
                Self(inner)
            }

            /// Copies the inner field element out for arithmetic.
            ///
            /// The caller is responsible for not letting the copy escape
            /// beyond the computation that needs it.
            pub fn expose(&self) -> $inner {
                self.0
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&REDACTED).finish()
            }
        }
    };
}

secret_field!(
    /// A secret Pallas scalar field element.
    SecretScalar,
    pallas::Scalar
);

secret_field!(
    /// A secret Pallas base field element.
    SecretBase,
    pallas::Base
);

#[cfg(test)]
mod tests {
    use ff::Field;
    use zeroize::Zeroize;

    use super::*;

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretScalar::new(pallas::Scalar::ONE);
        let printed = format!("{secret:?}");
        assert!(printed.contains(REDACTED));
        assert!(!printed.contains('1'));
    }

    #[test]
    fn zeroize_resets_to_zero() {
        let mut secret = SecretBase::new(pallas::Base::ONE);
        secret.zeroize();
        assert_eq!(secret.expose(), pallas::Base::ZERO);
    }

    #[test]
    fn constant_time_equality_agrees_with_eq() {
        let a = SecretScalar::new(pallas::Scalar::ONE);
        let b = SecretScalar::new(pallas::Scalar::ONE.double());
        assert!(bool::from(a.ct_eq(&a)));
        assert!(!bool::from(a.ct_eq(&b)));
    }
}

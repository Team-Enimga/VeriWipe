//! Sanitization Algorithm Patterns & Standard Definitions.
//! Implements NIST SP 800-88 Rev 1 (Clear & Purge) and DoD 5220.22-M NISPOM.

use crate::config::WipeMethod;
use rand::RngCore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwritePattern {
    Zero,
    One,
    PseudoRandom,
    Complement,
}

impl OverwritePattern {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Zero => "0x00 (Zero Fill)",
            Self::One => "0xFF (One Fill)",
            Self::PseudoRandom => "CSPRNG (Pseudo-Random Noise)",
            Self::Complement => "0x55 (Alternating Bit Inversion)",
        }
    }

    /// Fill a buffer according to this pattern
    pub fn fill_buffer(&self, buf: &mut [u8], rng: &mut impl RngCore) {
        match self {
            Self::Zero => buf.fill(0x00),
            Self::One => buf.fill(0xFF),
            Self::PseudoRandom => rng.fill_bytes(buf),
            Self::Complement => buf.fill(0x55),
        }
    }
}

pub struct WipePlan {
    pub method: WipeMethod,
    pub passes: Vec<OverwritePattern>,
}

impl WipePlan {
    pub fn for_method(method: WipeMethod) -> Self {
        let passes = match method {
            WipeMethod::Nist800_88Clear => vec![OverwritePattern::Zero],
            WipeMethod::Nist800_88Purge => vec![OverwritePattern::PseudoRandom, OverwritePattern::Zero],
            WipeMethod::Dod5220_22M => vec![
                OverwritePattern::Zero,
                OverwritePattern::One,
                OverwritePattern::PseudoRandom,
            ],
            WipeMethod::ZeroQuick => vec![OverwritePattern::Zero],
        };

        Self { method, passes }
    }
}

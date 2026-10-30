use std::ops::{Add, AddAssign, Sub, SubAssign};

const MAX_DIFF: u32 = u32::MAX / 2;

/// A TCP sequence number that persents a 32-bit unsigned integer, suppport overflow comparison and arithmetic.
#[derive(Eq, PartialEq, Debug, Copy, Clone, Hash, Default)]
#[repr(transparent)]
pub struct SeqNum(pub u32);

impl std::fmt::Display for SeqNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for SeqNum {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SeqNum> for u32 {
    fn from(value: SeqNum) -> Self {
        value.0
    }
}

impl From<SeqNum> for usize {
    fn from(value: SeqNum) -> Self {
        value.0 as usize
    }
}

impl TryFrom<usize> for SeqNum {
    type Error = std::io::Error;
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > u32::MAX as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("value 0x{value:X} is too large to convert to SeqNum"),
            ));
        }
        Ok(Self(value as u32))
    }
}

impl PartialEq<u32> for SeqNum {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl PartialOrd for SeqNum {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd<u32> for SeqNum {
    fn partial_cmp(&self, other: &u32) -> Option<std::cmp::Ordering> {
        Some(self.cmp(&SeqNum(*other)))
    }
}

impl Ord for SeqNum {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let diff = self.0.wrapping_sub(other.0);
        if diff == 0 {
            std::cmp::Ordering::Equal
        } else if diff < MAX_DIFF {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Less
        }
    }
}

impl Add for SeqNum {
    type Output = SeqNum;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        SeqNum(self.0.wrapping_add(rhs.0))
    }
}

impl Add<u32> for SeqNum {
    type Output = SeqNum;
    #[inline]
    fn add(self, rhs: u32) -> Self::Output {
        SeqNum(self.0.wrapping_add(rhs))
    }
}

impl AddAssign for SeqNum {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0.wrapping_add(rhs.0)
    }
}

impl AddAssign<u32> for SeqNum {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs)
    }
}

impl Sub for SeqNum {
    type Output = SeqNum;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        SeqNum(self.0.wrapping_sub(rhs.0))
    }
}

impl Sub<u32> for SeqNum {
    type Output = SeqNum;
    #[inline]
    fn sub(self, rhs: u32) -> Self::Output {
        SeqNum(self.0.wrapping_sub(rhs))
    }
}

impl SubAssign for SeqNum {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0.wrapping_sub(rhs.0)
    }
}

impl SubAssign<u32> for SeqNum {
    fn sub_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_sub(rhs)
    }
}

impl SeqNum {
    pub fn distance(&self, other: Self) -> u32 {
        let diff = self.0.wrapping_sub(other.0);
        if diff <= MAX_DIFF { diff } else { u32::MAX - diff + 1 }
    }
}

#[test]
fn test_seq_num_near_overflow() {
    let a: SeqNum = (u32::MAX - 3).into();
    let b = a + 8;

    assert_eq!(a, SeqNum(4294967292));
    assert_eq!(b, SeqNum(4));

    assert!(a < b);
    assert!(b > a);
    assert!(a <= b);
    assert!(b >= a);
    assert!(a != b);

    assert_eq!(a.distance(b), 8);
    assert_eq!(b.distance(a), 8);
}

#[test]
fn test_seq_num_near_max_diff() {
    let a = SeqNum(MAX_DIFF - 1);
    let mut b = SeqNum(MAX_DIFF + 1);

    assert!(a < b);
    assert!(b > a);
    assert_eq!(a.distance(b), 2);

    b += 3;
    assert_eq!(b.distance(a), 5);

    b -= 10;
    assert_eq!(b.distance(a), 5);

    assert_eq!(b, SeqNum(MAX_DIFF - 6));
}

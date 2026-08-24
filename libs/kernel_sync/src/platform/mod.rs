mod contract;

pub use contract::*;

#[cfg(feature = "std")]
pub mod std;

#[cfg(feature = "std")]
pub use self::std::StdPlatform;

#[cfg(all(feature = "std", windows))]
pub use self::std::WindowsPlatform;

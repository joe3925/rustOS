use alloc::{
    string::{String, ToString},
    vec::Vec,
};
// TODO: Switch to this at some point
#[derive(Debug, Clone)]
pub struct Path {
    pub drive: Option<char>,
    pub components: Vec<String>,
}

impl Path {
    pub fn from_string(abs: &str) -> Self {
        let b = abs.as_bytes();
        let mut drive = None;
        let mut start = 0;

        if b.len() >= 2 && b[1] == b':' && (b[0] as char).is_ascii_alphabetic() {
            drive = Some(b[0] as char);
            start = 2;
        }
        if b.get(start) == Some(&b'\\') || b.get(start) == Some(&b'/') {
            start += 1;
        } else {
            panic!("from_string() expects absolute path, got: {}", abs);
        }

        let comps = abs[start..]
            .split(['\\', '/'])
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        Self {
            drive,
            components: comps,
        }
    }

    pub fn parse(raw: &str, base: Option<&Self>) -> Self {
        let b = raw.as_bytes();

        if b.len() >= 2 && b[1] == b':' && (b[0] as char).is_ascii_alphabetic() {
            let d = b[0] as char;
            if b.len() == 2 {
                return Self {
                    drive: Some(d),
                    components: Vec::new(),
                };
            }
            if b.get(2) == Some(&b'\\') || b.get(2) == Some(&b'/') {
                return Self::from_string(raw);
            } else {
                if let Some(base) = base {
                    let mut out = base.clone();
                    out.drive = Some(d);
                    out.join(&raw[2..])
                } else {
                    panic!("Relative path {} given with no base", raw);
                }
            }
        } else if b.first() == Some(&b'\\') || b.first() == Some(&b'/') {
            if let Some(base) = base {
                let mut out = Self {
                    drive: base.drive,
                    components: Vec::new(),
                };
                out.join(&raw[1..])
            } else {
                panic!("Root-relative {} given with no base drive", raw);
            }
        } else {
            if let Some(base) = base {
                base.clone().join(raw)
            } else {
                panic!("Relative path {} given with no base", raw);
            }
        }
    }

    pub fn join(mut self, rel: &str) -> Self {
        for comp in rel.split(['\\', '/']) {
            if comp.is_empty() || comp == "." {
                continue;
            } else if comp == ".." {
                if !self.components.is_empty() {
                    self.components.pop();
                }
            } else {
                self.components.push(comp.to_string());
            }
        }
        self
    }

    pub fn normalize(&mut self) {
        let mut new_comps = Vec::new();
        for comp in &self.components {
            if comp == "." {
                continue;
            } else if comp == ".." {
                if !new_comps.is_empty() {
                    new_comps.pop();
                }
            } else {
                new_comps.push(comp.clone());
            }
        }
        self.components = new_comps;
    }

    pub fn to_string(&self) -> String {
        let mut out = String::new();
        if let Some(d) = self.drive {
            out.push(d);
            out.push(':');
        }
        out.push('\\');
        if !self.components.is_empty() {
            out.push_str(&self.components.join("\\"));
        }
        out
    }
}

#[derive(Debug, Copy, Clone)]
pub enum NetworkUpgrade {
    Bellatrix,
    Capella,
    Deneb,
}

impl NetworkUpgrade {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkUpgrade::Bellatrix => "Bellatrix",
            NetworkUpgrade::Capella => "Capella",
            NetworkUpgrade::Deneb => "Deneb",
        }
    }
}

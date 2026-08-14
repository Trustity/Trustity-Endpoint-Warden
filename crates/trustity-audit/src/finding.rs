use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Info,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Info => "INFO",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub status: Status,
    pub check: String,
    pub title: String,
    pub detail: String,
}

impl Finding {
    pub fn pass(check: impl Into<String>, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Pass,
            check: check.into(),
            title: title.into(),
            detail: detail.into(),
        }
    }

    pub fn warn(check: impl Into<String>, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Warn,
            check: check.into(),
            title: title.into(),
            detail: detail.into(),
        }
    }

    pub fn fail(check: impl Into<String>, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Fail,
            check: check.into(),
            title: title.into(),
            detail: detail.into(),
        }
    }

    pub fn info(check: impl Into<String>, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            status: Status::Info,
            check: check.into(),
            title: title.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub host: String,
    pub os: String,
    pub generated_at: String,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let mut pass = 0;
        let mut warn = 0;
        let mut fail = 0;
        let mut info = 0;
        for f in &self.findings {
            match f.status {
                Status::Pass => pass += 1,
                Status::Warn => warn += 1,
                Status::Fail => fail += 1,
                Status::Info => info += 1,
            }
        }
        (pass, warn, fail, info)
    }
}

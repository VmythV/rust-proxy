use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::{
    collections::HashMap,
    fs::File,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Default)]
pub struct Counts {
    pub up: AtomicU64,
    pub down: AtomicU64,
}
impl Counts {
    pub fn values(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
        )
    }
}
#[derive(Serialize)]
pub struct Row {
    id: i64,
    started: i64,
    ended: Option<i64>,
    protocol: String,
    method: String,
    target: String,
    upstream: String,
    status: Option<u16>,
    outcome: String,
    up: u64,
    down: u64,
}

pub struct Journal {
    db: Mutex<Connection>,
    active: Mutex<HashMap<i64, Arc<Counts>>>,
    _lock: File,
}
pub struct Entry {
    journal: Arc<Journal>,
    id: i64,
    pub counts: Arc<Counts>,
    pub status: Option<u16>,
    finished: bool,
}

impl Journal {
    pub fn open(path: &Path) -> Result<Arc<Self>> {
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.try_lock()
            .context("traffic database already in use or lock unavailable")?;
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS traffic(
                id INTEGER PRIMARY KEY, started INTEGER NOT NULL, ended INTEGER,
                protocol TEXT NOT NULL, method TEXT NOT NULL, target TEXT NOT NULL, upstream TEXT NOT NULL,
                status INTEGER, outcome TEXT NOT NULL DEFAULT 'active',
                up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS traffic_active ON traffic(id) WHERE ended IS NULL;")?;
        db.execute(
            "UPDATE traffic SET ended=?1, outcome='interrupted' WHERE ended IS NULL",
            [now()],
        )?;
        Ok(Arc::new(Self {
            db: Mutex::new(db),
            active: Mutex::default(),
            _lock: lock,
        }))
    }

    pub fn begin(
        self: &Arc<Self>,
        protocol: &str,
        method: &str,
        target: &str,
        upstream: &str,
    ) -> Result<Entry> {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO traffic(started,protocol,method,target,upstream) VALUES(?,?,?,?,?)",
            params![now(), protocol, method, target, upstream],
        )?;
        let id = db.last_insert_rowid();
        let counts = Arc::new(Counts::default());
        self.active.lock().unwrap().insert(id, counts.clone());
        Ok(Entry {
            journal: self.clone(),
            id,
            counts,
            status: None,
            finished: false,
        })
    }

    pub fn live(&self) -> (usize, u64, u64) {
        let active = self.active.lock().unwrap();
        let (up, down) = active
            .values()
            .map(|c| c.values())
            .fold((0, 0), |(a, b), (u, d)| (a + u, b + d));
        (active.len(), up, down)
    }

    pub fn rows(&self, before: Option<i64>, only_active: bool) -> Result<Vec<Row>> {
        let db = self.db.lock().unwrap();
        let condition = if only_active {
            " AND ended IS NULL"
        } else {
            ""
        };
        let mut stmt = db.prepare_cached(&format!(
            "SELECT id,started,ended,protocol,method,target,upstream,status,outcome,up,down
            FROM traffic WHERE id < ?{condition} ORDER BY id DESC LIMIT 101"
        ))?;
        let active = self.active.lock().unwrap();
        let rows = stmt
            .query_map([before.unwrap_or(i64::MAX)], |r| {
                let id = r.get(0)?;
                let (up, down) = match active.get(&id) {
                    Some(c) => c.values(),
                    None => (r.get(9)?, r.get(10)?),
                };
                Ok(Row {
                    id,
                    started: r.get(1)?,
                    ended: r.get(2)?,
                    protocol: r.get(3)?,
                    method: r.get(4)?,
                    target: r.get(5)?,
                    upstream: r.get(6)?,
                    status: r.get(7)?,
                    outcome: r.get(8)?,
                    up,
                    down,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }
}

impl Entry {
    pub fn finish(&mut self, outcome: &str) {
        if self.finished {
            return;
        }
        let db = self.journal.db.lock().unwrap();
        let (up, down) = self.counts.values();
        if let Err(e) = db.execute(
            "UPDATE traffic SET ended=?,status=?,outcome=?,up=?,down=? WHERE id=?",
            params![now(), self.status, outcome, up, down, self.id],
        ) {
            eprintln!("journal write failed: {e}");
        }
        self.journal.active.lock().unwrap().remove(&self.id);
        self.finished = true;
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.finish("interrupted");
    }
}

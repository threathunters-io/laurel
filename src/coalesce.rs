use std::collections::{HashMap,HashSet};
use std::error::Error;
use std::ops::Range;

use indexmap::IndexMap;

use serde::{Serialize,Serializer};
use serde::ser::{SerializeSeq,SerializeMap};

use crate::constants::msg_type::*;
use crate::proc::{ProcTable,Process,get_environ};
use crate::types::*;
use crate::parser::parse;

/// Collect records in [`EventBody`] context as single or multiple
/// instances.
///
/// Examples for single instances are `SYSCALL`,`EXECVE` (even if the
/// latter can be split across multiple lines). An example for
/// multiple instances is `PATH`.
///
/// "Multi" records are serialized as list-of-maps (`[ { "key":
/// "value", … }, { "key": "value", … } … ]`)
#[derive(Debug,Clone)]
pub enum EventValues {
    // e.g SYSCALL, EXECVE
    Single(Record),
    // e.g. PATH
    Multi(Vec<Record>),
}

impl Serialize for EventValues {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        match self {
            EventValues::Single(rv) => rv.serialize(serializer),
            EventValues::Multi(rvs) => {
                let mut seq = serializer.serialize_seq(Some(rvs.len()))?;
                for rv in rvs {
                    seq.serialize_element(rv)?;
                }
                seq.end()
            }
        }
    }
}

/// The content of an Event, sorted by message types
#[derive(Debug,Default)]
pub struct EventBody {
    values: IndexMap<MessageType,EventValues>,
    parent: Option<Process>,
}

#[derive(Debug)]
pub struct Event {
    id: EventID,
    body: EventBody,
}

impl Serialize for Event {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        let mut map = s.serialize_map(Some(1 +
                                           self.body.values.len() +
                                           if let None = self.body.parent {0} else {1} ))?;
        map.serialize_key("ID")?;
        map.serialize_value(&self.id)?;
        for (k,v) in &self.body.values {
            map.serialize_entry(&k,&v)?;
        }
        if let Some(p) = &self.body.parent {
            map.serialize_key("PARENT_INFO")?;
            map.serialize_value(&p)?;
        }
        map.end()
    }
}

/// Coalesce collects Audit Records from individual lines and assembles them to Events
#[derive(Debug,Default)]
pub struct Coalesce {
    /// Events that are being collected/processed
    inflight: HashMap<EventID,EventBody>,
    /// Event IDs that have been recently processed
    done: HashSet<EventID>,
    /// Timestamp for next cleanup
    next_expire: Option<u64>,
    /// process table built from observing process-related events
    processes: ProcTable,
    /// Generate ARGV and ARGV_STR from EXECVE
    pub execve_argv_list: bool,
    pub execve_argv_string: bool,
    pub execve_env: HashSet<Vec<u8>>,
}

const EXPIRE_PERIOD: u64  = 30_000;
const EXPIRE_TIMEOUT: u64 = 120_000;

impl Coalesce {
    /// Fill shadow process table from system's /proc directory
    pub fn populate_proc_table(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(self.processes = ProcTable::from_proc()?)
    }

    /// Cleans up stale "done" entries
    fn expire_done(&mut self, now: u64) {
        let ids = self.done.iter()
            .filter(|id| id.timestamp + EXPIRE_TIMEOUT > now)
            .copied()
            .collect::<Vec<_>>();
        for id in ids {
            self.done.remove(&id);
        }
        self.next_expire = Some(now + EXPIRE_PERIOD);
    }

    /// Rewrite EventBody to normal form
    ///
    /// This function
    /// - turns SYSCALL/a* fields into a single an ARGV list
    /// - turns EXECVE/a* and EXECVE/a*[*] fields into an ARGV list
    /// - turns PROCTITLE/proctitle into a (abbreviated) ARGV list
    fn normalize_eventbody(&self, eb: &mut EventBody) {
        if let Some(EventValues::Single(rv)) = eb.values.get_mut(&SYSCALL) {
            let mut new: Vec<(Key, Value)> = Vec::with_capacity(rv.elems.len() - 3);
            let mut argv: Vec<Value> = Vec::with_capacity(4 as usize);
            for item in 0..4 {
                if let Some(v) = rv.get(format!("a{}", item).as_bytes()) {
                    argv.push(v.value.clone());
                }
            }
            for (k,v) in &rv.elems {
                match k {
                    Key::Arg(_,_) | Key::ArgLen(_) => continue,
                    _ => new.push((k.clone(), v.clone())),
                };
            }
            new.push((Key::Literal("ARGV"), Value::List(argv)));
            rv.elems = new;
        }
        if let Some(EventValues::Single(rv)) = eb.values.get_mut(&EXECVE) {
            let mut new: Vec<(Key, Value)> = Vec::new();
            let mut argv: Vec<Value> = Vec::new();
            for (k, v) in rv.into_iter() {
                match k.key {
                    Key::ArgLen(_) => continue,
                    Key::Arg(i, None) => {
                        let idx = *i as usize;
                        if argv.len() <= idx {
                            argv.resize(idx+1, Value::Empty);
                        };
                        argv[idx] = v.value.clone();
                    },
                    Key::Arg(i, Some(f)) => {
                        let idx = *i as usize;
                        if argv.len() <= idx {
                            argv.resize(idx+1, Value::Empty);
                            argv[idx] = Value::Segments(Vec::new());
                        }
                        if let Some(Value::Segments(l)) = argv.get_mut(idx) {
                            let frag = *f as usize;
                            let r = match v.value {
                                Value::Str(r, _) => r,
                                _ => &Range{start: 0, end: 0}, // FIXME
                            };
                            if l.len() <= frag {
                                l.resize(frag+1, 0..0);
                                l[frag] = r.clone();
                            }
                        }
                    },
                    _ => new.push((k.key.clone(), v.value.clone())),
                };
            }
            if self.execve_argv_list {
                new.push((Key::Literal("ARGV"), Value::List(argv.clone())));
            }
            if self.execve_argv_string {
                new.push((Key::Literal("ARGV_STR"), Value::StringifiedList(argv.clone())));
            }
            rv.elems = new;
        }
        // Turn "sudo\x00ls\x00-l" into  "ARGV":["sudo","ls","-l"]
        if let Some(EventValues::Single(rv)) = eb.values.get_mut(&PROCTITLE) {
            if let Some(v) = rv.get(b"proctitle") {
                if let Value::Str(r, _) = v.value {
                    let mut argv: Vec<Value> = Vec::new();
                    let mut prev = r.start;
                    for i in r.start ..= r.end {
                        if (i == r.end || rv.raw[i] == 0) &&
                            !(prev..i).is_empty()
                        {
                            argv.push(Value::Str(prev..i, Quote::None));
                            prev = i+1;
                        }
                    }
                    rv.elems = vec!((Key::Literal("ARGV"), Value::List(argv)));
                }
            }
        }
    }

    /// Add environment variables to event body
    fn augment_execve_env(&mut self, execve: &mut Record, pid: u64) {
        if self.execve_env.is_empty() {
            return;
        }
        let vars = get_environ(pid).ok()
            .and_then( |environ| {
                let added = environ.iter()
                    .filter( |(k,_v)| self.execve_env.contains(k) )
                    .map( |(k,v)| {
                        let rk = execve.put(k);
                        let rv = execve.put(v);
                        (rk,rv)
                    })
                    .collect::<Vec<_>>();
                if added.len() > 0 { Some(added) } else { None }
            });
        match vars {
            Some(a) => {
                execve.elems.push( (Key::Literal("ENV"),Value::Map(a)) );
            }
            None => {}
        };
    }

    /// Augment event with information from shadow process table
    fn augment_syscall(&mut self, eb: &mut EventBody) {
        let sc = match eb.values.get(&SYSCALL) {
            Some(EventValues::Single(r)) => r,
            _ => return,
        };
        if let Some(v) = sc.get(b"ppid") {
            if let Value::Number(Number::Dec(ppid)) = v.value {
                eb.parent = self.processes.get_process(*ppid);
            }
        }
    }

    /// Ingest a log line and add it to the coalesce object.
    ///
    /// Simple one-liner events are returned immediately.
    ///
    /// For complex multi-line events (SYSCALL + additional
    /// information), corresponding records are collected and only the
    /// Event ID is returned. The entire event is returned only when
    /// an EOE ("end of event") line for the event is encountered.
    ///
    /// The line is consumed and serves as backing store for the
    /// EventBody objects.
    pub fn process_line(&mut self, line: Vec<u8>) -> Result<Option<Event>, Box<dyn Error>> {
        let (typ, id, rv) = parse(line)?;
        match self.next_expire {
            Some(t) if t < id.timestamp => {
                self.expire_done(id.timestamp);
                self.processes.expire();
            },
            None => self.next_expire = Some(id.timestamp + EXPIRE_PERIOD),
            _ => (),
        };
        match typ {
            SYSCALL => {
                if self.inflight.contains_key(&id) {
                    return Err(format!("duplicate SYSCALL for id {}", id).into());
                }
                let mut eb = EventBody::default();
                eb.values.insert(typ, EventValues::Single(rv));
                self.augment_syscall(&mut eb);
                self.inflight.insert(id, eb);
                return Ok(None);
            },
            EOE => {
                if self.done.contains(&id) {
                    return Err(format!("duplicate EOE for id {}", id).into());
                }
                self.done.insert(id);
                let mut eb = self.inflight.remove(&id).ok_or(format!("Event {} for EOE marker not found", &id))?;
                self.normalize_eventbody(&mut eb);

                let mut pid = None;
                if let Some(EventValues::Single(ref syscall)) = eb.values.get(&SYSCALL) {
                    #[allow(unused_must_use)]
                    if let Some(EventValues::Single(ref execve)) = eb.values.get(&EXECVE) {
                        self.processes.add_execve(&id, &syscall, &execve);
                    }
                    if let Some(v) = syscall.get(b"pid") {
                        if let Value::Number(Number::Dec(p)) = v.value {
                            pid = Some(*p);
                        }
                    }
                };
                match (pid, eb.values.get_mut(&EXECVE)) {
                    (Some(pid), Some(EventValues::Single(ref mut execve))) =>  {
                        self.augment_execve_env(execve, pid);
                    }
                    _ => (),
                };
                return Ok(Some(Event{id, body: eb}));
            },
            _ => {
                if let Some(eb) = self.inflight.get_mut(&id) {
                    match eb.values.get_mut(&typ) {
                        Some(EventValues::Single(v)) => v.extend(rv),
                        Some(EventValues::Multi(v)) => v.push(rv),
                        None => match typ {
                            EXECVE | PROCTITLE | CWD => {
                                eb.values.insert(typ, EventValues::Single(rv));
                            },
                            _ => {
                                eb.values.insert(typ, EventValues::Multi(vec!(rv)));
                            },
                        }
                    };
                    Ok(None)
                } else {
                    self.done.insert(id);
                    let mut values = IndexMap::new();
                    values.insert(typ, EventValues::Single(rv));
                    Ok(Some(Event{id, body: EventBody{values, parent: None}}))
                }
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::{BufReader,BufRead};

    #[test]
    fn coalesce() -> Result<(), String> {
        let mut c = Coalesce { execve_argv_list: true, ..Coalesce::default() };

        match c.process_line(
            Vec::from(*include_bytes!("testdata/line-user-acct.txt"))
        ).unwrap() {
            None => panic!("failed to emit event body"),
            Some(eb) => println!("got {:?}", eb),
        };

        let mut event = None;
        for line in BufReader::new(include_bytes!("testdata/record-execve.txt").as_ref()).lines() {
            let mut line = line.unwrap().clone();
            line.push('\n');
            match c.process_line(line.as_bytes().to_vec())
                .expect(format!("failed to parse {:?}", line).as_str())
            {
                Some(o) => {
                    event = Some(o);
                    break;
                }
                None => (),
            }
        }
        match event {
            None => panic!("failed to emit event bodyr"),
            Some(eb) => println!("got {:?}", eb),
        };
        Ok(())
    }

    #[test]
    fn coalesce_long() -> Result<(), String> {
        let mut c = Coalesce { execve_argv_list: true, ..Coalesce::default() };

        let mut event = None;
        for line in BufReader::new(include_bytes!("testdata/record-execve-long.txt").as_ref()).lines() {
            let mut line = line.unwrap().clone();
            line.push('\n');
            match c.process_line(line.as_bytes().to_vec())
                .expect(format!("failed to parse {:?}", line).as_str())
            {
                Some(o) => {
                    event = Some(o);
                    break;
                }
                None => (),
            }
        }
        match event {
            None => panic!("failed to emit event bodyr"),
            Some(eb) => println!("got {:?}", eb),
        };
        Ok(())
    }
}

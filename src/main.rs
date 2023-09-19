use clap::Parser;
use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{self, BufRead, BufReader},
};

/// stackcollapse-perf in rust.
/// Based on an existing project (https://github.com/brendangregg/FlameGraph/blob/master/stackcollapse-perf.pl), and an existing port of that project (https://github.com/jonhoo/inferno/blob/master/src/collapse/perf.rs).
/// Main difference between this version and the initial version of the existing port are that this uses nom to parse.
/// This is a learning project, and is in no way even close to offering the features the original or existing ported versions do!
#[derive(Parser, Debug)]
#[clap(
    name = "amadou-collapse-perf",
    about,
    after_help = "\
[1] perf script must emit both PID and TIDs for these to work; eg, Linux < 4.1:
        perf script -f comm,pid,tid,cpu,time,event,ip,sym,dso,trace
    for Linux >= 4.1:
        perf script -F comm,pid,tid,cpu,time,event,ip,sym,dso,trace
    If you save this output add --header on Linux >= 3.14 to include perf info."
)]
struct Args {
    /// include PID with process names [1]
    #[clap(long = "pid")]
    include_pid: bool,

    /// include TID and PID with process names [1]
    #[clap(long = "tid", requires("pid"))]
    include_tid: bool,

    /// annotate kernel functions with a _[k]
    #[clap(long = "kernel")]
    annotate_kernel: bool,

    /// annotate jit functions with a _[j]
    #[clap(long = "jit")]
    annotate_jit: bool,

    /// include raw addresses where symbols can't be found
    #[clap(long = "addrs")]
    include_addrs: bool,

    /// perf script output file, or STDIN if not specified
    #[clap(value_name = "PATH")]
    infile: Option<String>,
}

fn main() -> io::Result<()> {
    // TODO: all option means both jit and kernel
    // TODO: more clearly set default options
    // TODO: So much error handling
    let args = Args::parse();

    match args.infile {
        Some(ref file) => {
            let reader = BufReader::with_capacity(128 * 1024, File::open(file)?);
            handle_file(args, reader)
        }
        None => {
            let stdin = io::stdin();
            let reader = BufReader::with_capacity(128 * 1024, stdin.lock());
            handle_file(args, reader)
        }
    }
}

/// Processes event/stack data into folded version suitable for flamegraph
fn handle_file<R: BufRead>(args: Args, mut reader: R) -> io::Result<()> {
    let mut line = String::new();
    let mut state = PerfState::from(args);

    while let Ok(bytes) = reader.read_line(&mut line) {
        if bytes == 0 {
            break;
        }
        let current_line = line.trim();

        // skip comments
        if !current_line.starts_with('#') {
            // events/stack combinations are separated by empty lines, so once we reach a new line, we assume we are starting an a new event, and new associated stack
            if current_line.is_empty() {
                state.after_event();
            } else {
                state.on_line(current_line);
            }
        }
        line.clear();
    }
    state.finish();

    Ok(())
}

#[derive(Debug)]
struct PerfState {
    process_name: String,
    stack: VecDeque<String>,
    occurrences: HashMap<String, i32>,
    args: Args,
}

impl From<Args> for PerfState {
    fn from(args: Args) -> Self {
        PerfState {
            process_name: String::default(),
            stack: VecDeque::default(),
            occurrences: HashMap::default(),
            args,
        }
    }
}

impl PerfState {
    fn on_line(&mut self, line: &str) {
        if self.process_name.is_empty() {
            self.on_event_line(line);
        } else {
            self.on_stack_line(line);
        }
    }

    fn on_event_line(&mut self, line: &str) {
        // event lines are structured as: <COMM> <PID'/'TID or only TID> ... <EVENT>

        // TODO: event filtering
        // TODO: handle cases with combined event/stack lines
        if let Ok((.., (process_name, pid, tid))) = perf_report_parser::parse_comm_pid_tid(line) {
            self.process_name = process_name;
            if self.args.include_pid {
                self.process_name.push('-');
                self.process_name.push_str(pid);
                if self.args.include_tid {
                    self.process_name.push('/');
                    self.process_name.push_str(tid);
                }
            }
        }
    }

    fn on_stack_line(&mut self, line: &str) {
        // stack lines are structured as: <PROGRAM_COUNTER> <FUNCTION> <MODULE>

        // TODO: There should always be a function, but only possibly be a module (a module without surrounding parenthesis should automatically be discounted) -- this needs to be properly reflected
        if let (.., (_program_counter, Some(mut function), Some(module))) =
            perf_report_parser::parse_stack_line(line, self.args.include_addrs).unwrap()
        {
            // TODO: find correct expected inputs to make source's TIDY_GENERIC function correctly
            // TODO: find fully enumerated list of options under which annotations apply, as to ensure this behavior is correct (& also move into separate function)

            if self.args.annotate_kernel
                && (module.starts_with('[') || module.ends_with("vmlinux"))
                && module != "[unknown]"
            {
                function.push_str("_[k]");
            } else if self.args.annotate_jit
                && ((module.starts_with("/tmp/perf-") && module.ends_with(".map"))
                    || (module.contains("/jitted-") && module.ends_with(".so")))
            {
                function.push_str("_[j]");
            }

            self.stack.push_front(function);
        }
    }

    fn after_event(&mut self) {
        let mut stack_line = String::with_capacity(
            self.process_name.len() + 1 + self.stack.iter().fold(0, |acc, s| acc + s.len() + 1),
        );
        stack_line.push_str(&self.process_name);
        for e in self.stack.drain(..) {
            stack_line.push(';');
            stack_line.push_str(&e);
        }

        *self.occurrences.entry(stack_line).or_insert(0) += 1;

        self.process_name.clear();
        self.stack.clear();
    }

    fn finish(&mut self) {
        let mut keys = self.occurrences.keys().collect::<Vec<_>>();
        keys.sort();
        for key in keys {
            println!("{key} {}", self.occurrences[key]);
        }
    }
}

mod perf_report_parser {
    use nom::{
        branch::alt,
        bytes::complete::{tag, take_until, take_until1},
        character::complete::{char, digit1, multispace1},
        combinator::{eof, map, opt, peek, recognize},
        multi::many_till,
        sequence::{pair, terminated},
        IResult,
    };

    fn pid(input: &str) -> IResult<&str, Option<&str>> {
        opt(terminated(digit1, char('/')))(input)
    }

    fn tid(input: &str) -> IResult<&str, &str> {
        digit1(input)
    }

    fn _event(input: &str) -> IResult<&str, &str> {
        recognize(many_till(
            alt((tag(":"), take_until(":"))),
            peek(pair(tag(":"), eof)),
        ))(input.split_whitespace().last().unwrap())
    }

    fn pid_tid(input: &str) -> IResult<&str, (Option<&str>, &str)> {
        terminated(pair(pid, tid), multispace1)(input)
    }

    fn comm_pid_tid(input: &str) -> IResult<&str, (Vec<&str>, Option<&str>, &str)> {
        let (input, (comm, (pid, tid))) =
            many_till(terminated(take_until1(" "), multispace1), pid_tid)(input)?;

        Ok((input, (comm, pid, tid)))
    }

    pub fn parse_comm_pid_tid(input: &str) -> IResult<&str, (String, &str, &str)> {
        map(comm_pid_tid, |(process_name, pid, tid)| {
            (process_name.join("_"), pid.unwrap_or("?"), tid)
        })(input)
    }

    pub fn _parse_comm_pid_tid_event(input: &str) -> IResult<&str, (String, &str, &str, &str)> {
        map(
            pair(comm_pid_tid, _event),
            |((process_name, pid, tid), event)| {
                (process_name.join("_"), pid.unwrap_or("?"), tid, event)
            },
        )(input)
    }

    pub fn parse_stack_line(
        input: &str,
        include_addrs: bool,
    ) -> IResult<&str, (&str, Option<String>, Option<&str>)> {
        let (program_counter, input) = input.split_once(' ').unwrap();
        let (input, module) = input.rsplit_once(' ').unwrap();
        let module = if module.starts_with('(') && module.ends_with(')') {
            Some(module.trim_end_matches(')').trim_start_matches('('))
        } else {
            None
        };
        let mut function = input;

        if function.starts_with('(') {
            Ok((input, (program_counter, None, module)))
        } else {
            function = function
                .rsplit_once("+0x")
                .map(|(f, _)| f)
                .filter(|f| f.chars().all(|c| c.is_ascii_hexdigit()))
                .unwrap_or(function);

            // TODO: apparently perf will sometimes fail to correctly demangle rust symbols sometimes, so this needs to be corrected here
            // TODO: find correct expected inputs to make source's TIDY_GENERIC function correctly
            // TODO: original source has inlining for java functions & TIDY_JAVA -- are these necessary for anything other than java, and if not, do we keep the behavior ?
            // TODO: error handling !  This function returns a result, but the operation of dependant functions relies on the values of returned options wrapped in the Ok case ??? (I think the logic for this whole function needs to be reassessed).

            let function = if function == "[unknown]" {
                let function = match (module, include_addrs) {
                    (Some("[unknown]"), true) => "unknown",
                    (Some("[unknown]"), false) => {
                        return Ok(("", (program_counter, Some(function.to_string()), module)))
                    }
                    (Some(module), _) => &module[module.rfind('/').map(|i| i + 1).unwrap_or(0)..],
                    _ => "unknown",
                };

                let mut f = String::with_capacity(function.len() + program_counter.len() + 5);

                if include_addrs {
                    f.push('[');
                    f.push_str(function);
                    f.push_str(" <");
                    f.push_str(program_counter);
                    f.push_str(">]");
                    f
                } else {
                    f.push('[');
                    f.push_str(function);
                    f.push(']');
                    f
                }
            } else {
                function.to_string()
            };

            Ok(("", (program_counter, Some(function), module)))
        }
    }
}

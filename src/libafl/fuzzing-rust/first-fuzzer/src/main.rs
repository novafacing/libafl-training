#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use libafl::prelude::InMemoryCorpus;
use libafl::prelude::InProcessExecutor;
use libafl::prelude::OnDiskCorpus;
use libafl::prelude::QueueScheduler;
use libafl::prelude::SimpleEventManager;
use libafl::prelude::SimpleMonitor;
use libafl::prelude::{havoc_mutations, StdScheduledMutator};
use libafl::prelude::{AflMapFeedback, CrashFeedback, HitcountsIterableMapObserver};
use libafl::prelude::{BytesInput, ExitKind, HasTargetBytes};
use libafl::stages::StdMutationalStage;
use libafl::{Fuzzer, StdFuzzer};
use libafl_bolts::AsSlice;
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list};
use libafl_targets::CountersMultiMapObserver;
use mimalloc::MiMalloc;
use std::path::PathBuf;

use libafl::state::StdState;

extern "Rust" {
    fn decode(encoded_input: &[u8]) -> Vec<u8>;
    fn counters_maps_observer(name: &'static str) -> CountersMultiMapObserver<false>;
}

use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    /// Corpus directory
    corpus: PathBuf,
    #[arg(short, long)]
    /// Solutions directory
    solutions: PathBuf,
}

fn main() {
    let args = Args::parse();

    let rand = StdRand::with_seed(current_nanos());
    let corpus = InMemoryCorpus::new();
    let solutions = OnDiskCorpus::new(&args.solutions).unwrap_or_else(|e| {
        panic!(
            "Unable to create OnDiskCorpus at {}: {}",
            args.solutions.display(),
            e
        )
    });

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        println!("Fuzzing with {:?} ({})", buf, buf.len());
        unsafe { decode(buf) };
        ExitKind::Ok
    };

    let counters_observer =
        HitcountsIterableMapObserver::new(unsafe { counters_maps_observer("counters-maps") });
    let mut counters_feedback = AflMapFeedback::new(&counters_observer);
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        rand,
        corpus,
        solutions,
        &mut counters_feedback,
        &mut objective,
    )
    .expect("Failed to create state");

    let mon = SimpleMonitor::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(mon);
    let mutator = StdScheduledMutator::new(havoc_mutations());

    let scheduler = QueueScheduler::new();
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let mut fuzzer = StdFuzzer::new(scheduler, counters_feedback, objective);

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(counters_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    state
        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[args.corpus])
        .expect("Failed to generate the initial corpus");

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

// Maybenot Surakav -- uses constant-rate traffic to approximate the Surakav defense
// Code from the paper "State Machine Frameworks for Website Fingerprinting Defenses: Maybe Not"

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashMap;
use std::f64::INFINITY;

use maybenot::{
machine::Machine,
event::Event,
state::State,
dist::{Dist, DistType}
};

const TOR_CELL_SIZE: f64   = 512.0;
const CUTOFF_LENGTH: usize = 8000; // bursts

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 2, "Usage: {} <ref trace path>", &args[0]);
    
    let (client_machine, relay_machine) = parse_file(&args[1]);
    println!("Client machine: {} ({})\n", client_machine, client_machine.len());
    println!("Relay machine: {} ({})\n", relay_machine, relay_machine.len());
}

// Takes reference traces and returns Surakav client and relay machines
fn parse_file(burst_file: &str) -> (String, String) {
    let (lines, num_bursts) = read_lines(burst_file);
    
    // Machine info
    let num_states = num_bursts + 2;
    
    // Generate states
    let mut relay_states: Vec<State> = Vec::with_capacity(num_states);
    let mut client_states: Vec<State> = Vec::with_capacity(num_states);
    
    relay_states.push(generate_start_state(1, num_states));
    relay_states.push(generate_block_state(2, num_states));
    
    client_states.push(generate_start_state(1, num_states));
    client_states.push(generate_block_state(2, num_states));
    
    // After START + BLOCK states:
    // client   -->  SEND  --> (RECV) --> ... --> StateEnd
    // relay    --> (RECV) -->  SEND  --> ... --> StateEnd
    let mut curr_idx: usize = 2;
    let mut next_idx: usize = 3;
    let mut relay_sending = false;

    for lines_idx in 0..(lines.len()) {
        if lines[lines_idx] == 0 {
            relay_sending = !relay_sending;
            continue;
        }
        
        let (send_state, recv_state) = generate_burst_states(lines[lines_idx] as f64, curr_idx, next_idx, num_states);
        
        if relay_sending {
            relay_states.push(send_state);
            client_states.push(recv_state);
        } else {
            relay_states.push(recv_state);
            client_states.push(send_state);
        }
        
        curr_idx += 1;
        next_idx += 1;
        if next_idx == num_states {
            next_idx = num_states + 1; // StateEnd
        }
        relay_sending = !relay_sending;
    }
    
    // Generate machine
    let relay_machine = Machine {
        allowed_padding_bytes: u64::MAX,
        max_padding_frac: 0.0,
        allowed_blocked_microsec: u64::MAX,
        max_blocking_frac: 0.0,
        states: relay_states,
        include_small_packets: false,
    };
    let client_machine = Machine {
        allowed_padding_bytes: u64::MAX,
        max_padding_frac: 0.0,
        allowed_blocked_microsec: u64::MAX,
        max_blocking_frac: 0.0,
        states: client_states,
        include_small_packets: false,
    };
    
    return (relay_machine.serialize(), client_machine.serialize());
}

// Generate a START state. This is used as the initial state in a machine.
fn generate_start_state(next_index: usize, num_states: usize) -> State {
    let mut nonpadding_sent: HashMap<usize, f64> = HashMap::new();
    nonpadding_sent.insert(next_index, 1.0);
    
    let mut nonpadding_recv: HashMap<usize, f64> = HashMap::new();
    nonpadding_recv.insert(next_index, 1.0);
    
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::NonPaddingSent, nonpadding_sent);
    transitions.insert(Event::NonPaddingRecv, nonpadding_recv);
    
    return State::new(transitions, num_states);
}

// Generate a BLOCK state. This is used to enable infinite blocking after the START state.
fn generate_block_state(next_index: usize, num_states: usize) -> State {
    // Transitions
    let mut blocking_begin: HashMap<usize, f64> = HashMap::new();
    blocking_begin.insert(next_index, 1.0);
    
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::BlockingBegin, blocking_begin);
    
    let mut state = State::new(transitions, num_states);
    state.action_is_block = true;
    state.bypass = true;
    state.replace = true;
    
    state.timeout = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    
    state.action = Dist {
        dist: DistType::Uniform,
        param1: INFINITY,
        param2: INFINITY,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}

fn generate_burst_states(num_cells: f64, curr_index: usize, next_index: usize, num_states: usize) -> (State, State) {
    // Transitions
    let mut limit_reached_send: HashMap<usize, f64> = HashMap::new();
    let mut limit_reached_recv: HashMap<usize, f64> = HashMap::new();
    limit_reached_send.insert(next_index, 1.0);
    limit_reached_recv.insert(next_index, 1.0);
    
    let mut padding_sent: HashMap<usize, f64> = HashMap::new();
    padding_sent.insert(curr_index, 1.0);
    
    let mut nonpadding_recv: HashMap<usize, f64> = HashMap::new();
    nonpadding_recv.insert(curr_index, 1.0);
    
    let mut padding_recv: HashMap<usize, f64> = HashMap::new();
    padding_recv.insert(curr_index, 1.0);
    
    let mut transitions_send: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    let mut transitions_recv: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    
    transitions_send.insert(Event::LimitReached, limit_reached_send);
    transitions_send.insert(Event::PaddingSent, padding_sent);
    
    transitions_recv.insert(Event::LimitReached, limit_reached_recv);
    transitions_recv.insert(Event::NonPaddingRecv, nonpadding_recv);
    transitions_recv.insert(Event::PaddingRecv, padding_recv);
    
    // States
    let mut send_state = State::new(transitions_send, num_states);
    let mut recv_state = State::new(transitions_recv, num_states);
    
    send_state.bypass = true;
    send_state.replace = true;
    
    recv_state.action_is_block = true;
    recv_state.bypass = true;
    recv_state.replace = true;
    
    send_state.timeout = Dist {
        dist: DistType::Uniform,
        param1: 5.0,
        param2: 5.0,
        start: 0.0,
        max: 0.0,
    };
    recv_state.timeout = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    
    send_state.action = Dist {
        dist: DistType::Uniform,
        param1: TOR_CELL_SIZE,
        param2: TOR_CELL_SIZE,
        start: 0.0,
        max: 0.0,
    };
    recv_state.action = Dist {
        dist: DistType::Uniform,
        param1: INFINITY,
        param2: INFINITY,
        start: 0.0,
        max: 0.0,
    };
    
    send_state.limit = Dist {
        dist: DistType::Uniform,
        param1: num_cells,
        param2: num_cells,
        start: 0.0,
        max: 0.0,
    };
    recv_state.limit = Dist {
        dist: DistType::Uniform,
        param1: num_cells,
        param2: num_cells,
        start: 0.0,
        max: 0.0,
    };
    
    return (send_state, recv_state);
}

fn read_lines(filename: &str) -> (Vec<usize>, usize) {
    let file = File::open(filename).expect("Couldn't open trace file");
    let reader = BufReader::new(file);

    let mut lines: Vec<usize> = Vec::new();
    let mut count: usize = 0;

    for (_, line) in reader.lines().enumerate() {
        if count >= CUTOFF_LENGTH {
            break;
        }
        
        if let Ok(ip) = line {
            let val: u32 = ip.parse().expect("Line not formatted properly");
            lines.push(val as usize);
            if val != 0 {
                count += 1;
            }
        }
    }

    return (lines, count);
}

// Maybenot FRONT -- uses normally distributed padding to approximate the FRONT defense
// Code from the paper "State Machine Frameworks for Website Fingerprinting Defenses: Maybe Not"

use std::env;
use std::f64::EPSILON;
use std::f64::consts::E;
use std::f64::consts::PI;
use std::collections::HashMap;

use maybenot::{
machine::Machine,
event::Event,
state::State,
dist::{Dist, DistType}
};

const TOR_CELL_SIZE: f64 = 512.0;

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 4, "Usage: {} <padding window> <padding budget> <num states>", &args[0]);
    
    let padding_window: f64 = args[1].parse().expect("Invalid padding window"); // FRONT param = W_max (sec)
    let padding_budget: u32 = args[2].parse().expect("Invalid padding budget"); // FRONT param = N (num cells)
    let num_states:     u32 = args[3].parse().expect("Invalid num states");     // number of PADDING states
    
    let machine = generate_machine(padding_window * 1000000.0, padding_budget, num_states as usize);
    println!("Machine: {} ({})\n", machine, machine.len());
}

// Generate a FRONT machine with the specified number of PADDING states.
fn generate_machine(padding_window: f64, padding_budget: u32, num_states: usize) -> String {
    let area = 1.0 / (num_states as f64);       // Area under Rayleigh CDF curve of each state
    let max_t = rayleigh_max_t(padding_window);
    
    // States
    let mut states: Vec<State> = Vec::with_capacity(num_states + 1);
    states.push(generate_start_state(num_states + 1));
    
    let mut t1 = 0.0;                           // Starting time of next PADDING state
    let mut total_padding_frac = 0.0;           // Area coverage of current PADDING states
    
    for i in 1..num_states {
        let width = calc_interval_width(t1, max_t, area, padding_window);
        let middle = t1 + (width / 2.0);
        let t2 = t1 + width;
        
        let padding_count = area * (padding_budget as f64);
        let timeout = width / padding_count;
        let stdev = (padding_window).powi(2) / (padding_count * middle * PI.sqrt());
        
        states.push(generate_padding_state(i, i + 1, num_states + 1, padding_count, timeout, stdev));
        
        t1 = t2;
        total_padding_frac += area;
    }
    
    // Last state, to max_t
    let width = max_t - t1;
    let middle = t1 + (width / 2.0);
    
    let padding_count = (1.0 - total_padding_frac) * (padding_budget as f64);
    let timeout = width / padding_count;
    let stdev = (padding_window).powi(2) / (padding_count * middle * PI.sqrt());
    
    states.push(generate_padding_state(num_states, num_states + 2, num_states + 1, padding_count, timeout, stdev));
    
    // Machine
    let machine = Machine {
        allowed_padding_bytes: u64::MAX,
        max_padding_frac: 0.0,
        allowed_blocked_microsec: 0,
        max_blocking_frac: 0.0,
        states: states,
        include_small_packets: false,
    };
    
    return machine.serialize();
}

// Generate a PADDING state for a machine.
fn generate_padding_state(curr_index: usize, next_index: usize, num_states: usize, padding_count: f64, timeout: f64, stdev: f64) -> State {
    // PaddingSent --> this PADDING state (100%)
    let mut padding_sent: HashMap<usize, f64> = HashMap::new();
    padding_sent.insert(curr_index, 1.0);
    
    // LimitReached --> next PADDING state or StateEnd (100%)
    let mut limit_reached: HashMap<usize, f64> = HashMap::new();
    limit_reached.insert(next_index, 1.0);
    
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::PaddingSent, padding_sent);
    transitions.insert(Event::LimitReached, limit_reached);
    
    let mut state = State::new(transitions, num_states);
    
    state.timeout = Dist {
        dist: DistType::Normal,
        param1: timeout,
        param2: stdev,
        start: 0.0,
        max: (timeout * 2.0),
    };
    
    state.action = Dist {
        dist: DistType::Uniform,
        param1: TOR_CELL_SIZE,
        param2: TOR_CELL_SIZE,
        start: 0.0,
        max: 0.0,
    };
    
    state.limit = Dist {
        dist: DistType::Uniform,
        param1: 1.0,
        param2: padding_count,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}

// Generate the START state for a machine.
fn generate_start_state(num_states: usize) -> State {
    // NonPaddingSent --> first PADDING state (100%)
    let mut nonpadding_sent: HashMap<usize, f64> = HashMap::new();
    nonpadding_sent.insert(1, 1.0);
    
    // NonPaddingRecv --> first PADDING state (100%)
    let mut nonpadding_recv: HashMap<usize, f64> = HashMap::new();
    nonpadding_recv.insert(1, 1.0);
    
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::NonPaddingSent, nonpadding_sent);
    transitions.insert(Event::NonPaddingRecv, nonpadding_recv);
    
    return State::new(transitions, num_states);
}

// Find the width of an interval in the Rayleigh distribution,
// starting at a, with the specified area. Uses a search algorithm
// because numerical error affects direct calculation significantly.
fn calc_interval_width(a: f64, max_t: f64, area: f64, scale: f64) -> f64 {
    let mut b = max_t;
    let mut increment = (b - a) / 2.0;
    
    let mut curr_area = rayleigh_cdf(b, scale) - rayleigh_cdf(a, scale);
    let mut curr_diff = area - curr_area;
    
    while curr_diff.abs() > EPSILON {
        if curr_diff < 0.0 {
            b -= increment;
        } else {
            b += increment;
        }
        increment /= 2.0;
        
        curr_area = rayleigh_cdf(b, scale) - rayleigh_cdf(a, scale);
        curr_diff = area - curr_area;
    }
    
    return b - a;
}

// Cumulative distribution function of Rayleigh distribution
fn rayleigh_cdf(t: f64, scale: f64) -> f64 {
    let exp_num = -t.powi(2);
    let exp_div = 2.0 * scale.powi(2);
    let exp = exp_num / exp_div;
    
    return 1.0 - E.powf(exp);
}

// Return the value of t (input to Rayleigh CDF) at which area = 0.9996645373720975, chosen
// empirically. This is a bit more than 6 standard deviations.
fn rayleigh_max_t(scale: f64) -> f64 {
    let a: f64 = -2.0 * scale.powi(2);
    let b: f64 = 1.0 - 0.9996645373720975;
    
    return (a * b.log(E)).sqrt();
}

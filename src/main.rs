extern crate zxcvbn;
use rand::Rng;
use clap::Parser;
use zxcvbn::zxcvbn;

const NUMBERS: [char; 8] = [
    '2','3','4','5','6','7','8','9'
];

const LOWERS: [char; 25] = [
    'a','b','c','d','e','f','g','h','i','j','k','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
];

const UPPERS: [char; 24] = [
    'A','B','C','D','E','F','G','H','J','K','L','M',
    'N','P','Q','R','S','T','U','V','W','X','Y','Z',
];

const ALL_LETTERS: [char; 59] = [
    'a','b','c','d','e','f','g','h','i','j','k','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','J','K','L','M',
    'N','P','Q','R','S','T','U','V','W','X','Y','Z',
    '.','-',
    '2','3','4','5','6','7','8','9'
];

fn gen_letter(rng: &mut rand::rngs::ThreadRng) -> char {
    let i = rng.gen_range(0..ALL_LETTERS.len());
    return ALL_LETTERS[i];
}

fn gen_upper(rng: &mut rand::rngs::ThreadRng) -> char {
    let i = rng.gen_range(0..UPPERS.len());
    return UPPERS[i];
}

fn has_num(pw: &[char]) -> bool {
    for i in 0..pw.len() {
        for j in 0..NUMBERS.len() {
            if pw[i] == NUMBERS[j] {
                return true;
            }
        }
    }
    return false;
}

fn has_lower(pw: &[char]) -> bool {
    for i in 0..pw.len() {
        for j in 0..LOWERS.len() {
            if pw[i] == LOWERS[j] {
                return true;
            }
        }
    }
    return false;
}

fn has_upper(pw: &[char]) -> bool {
    for i in 0..pw.len() {
        for j in 0..UPPERS.len() {
            if pw[i] == UPPERS[j] {
                return true;
            }
        }
    }
    return false;
}

fn has_spec(pw: &[char]) -> bool {
    for i in 0..pw.len() {
        if pw[i] == '-' || pw[i] == '.' {
            return true;
        }
    }
    return false;
}

fn has_repeat(pw: &[char]) -> bool {
    for i in 1..pw.len() {
        if pw[i] == pw[i-1] {
            return true;
        }
    }
    return false;
}

fn has_morse(pw: &[char]) -> bool {
    for i in 1..pw.len() {
        if (pw[i] == '.' && pw[i-1] == '-')
            || (pw[i] == '-' && pw[i-1] == '.') {
            return true;
        }
    }
    return false;
}

fn gen_candidate(rng: &mut rand::rngs::ThreadRng, arr: &mut[char]) {
    arr[0] = gen_upper(rng);
    for i in 1..arr.len()-1 {
        arr[i] = gen_letter(rng);
    }
    arr[arr.len()-1] = gen_upper(rng);
}

fn pwgen(rng: &mut rand::rngs::ThreadRng, chars: &mut[char]) {
    let minscore = if chars.len() < 11 {3} else {4};
    loop {
        gen_candidate(rng, chars);
        if !has_num(chars) {
            continue;
        }
        if !has_spec(chars) {
            continue;
        }
        if !has_upper(chars) {
            continue;
        }
        if !has_lower(chars) {
            continue;
        }
        if has_repeat(chars) {
            continue;
        }
        if has_morse(chars) {
            continue;
        }
        let pws: String = chars.iter().collect();
        let estimate = zxcvbn(&pws, &[]).unwrap();
        if estimate.score() < minscore {
            continue;
        }
        break;
    }
}

/// The Best PassWord Generator
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Size of the password
    #[clap(short, long, default_value_t = 12)]
    size: usize,
}

fn main() {
    let args = Args::parse();
    let size = if args.size < 9 {9} else {args.size};
    let mut rng = rand::thread_rng();
    let mut pw = vec!['_'; size];
    pwgen(&mut rng, &mut pw);
    let pws: String = pw.iter().collect();
    println!("{}", pws);
}

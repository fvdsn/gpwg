use rand::Rng;
use clap::{Arg, Command};
use zxcvbn::zxcvbn;
use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;
use std::{thread, time};


// Constants that control the shape of the generated password
const STRONG_SIZE: usize = 32;
const DEFAULT_SIZE: usize = 18;
const MIN_SIZE: usize = 8;
const MAX_SIZE: usize = 104;

// The two special characters
//  - accepted by most password restrictions
//  - on first screen of iphone keyboard
//  - available on most keyboards
//  - rarely need to be escaped
const SPEC1: char = '!';
const SPEC2: char = '@';

// Block separator for long passwords
const SPECSEP: char = '-';
// Size of blocks for long passwords
const SPECSEP_BLOCKSIZE: usize = 8;
const SPECSEP_MINSIZE: usize = 24;

// List of number charcters
// 1 and 0 have been removed as they look similar to l,I and O
const NUMBERS: [char; 8] = [
    '2','3','4','5','6','7','8','9'
];

// List of lower charcters
// l has been removed as it looks similar to I
const LOWERS: [char; 25] = [
    'a','b','c','d','e','f','g','h','i','j','k','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
];

// List of upper characters
// I, O have been removed as they look similar to 1,l and 0
const UPPERS: [char; 24] = [
    'A','B','C','D','E','F','G','H','J','K','L','M',
    'N','P','Q','R','S','T','U','V','W','X','Y','Z',
];

// Letters of all cases + special characters
const ALL_LETTERS: [char; 59] = [
    'a','b','c','d','e','f','g','h','i','j','k','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','J','K','L','M',
    'N','P','Q','R','S','T','U','V','W','X','Y','Z',
    SPEC1, SPEC2,
    '2','3','4','5','6','7','8','9'
];

// map of password length to entropy
const PW_ENTROPY: [[usize; 2]; 25] = [
    [8,41],
    [9,47],
    [10,53],
    [11,59],
    [12,65],
    [13,71],
    [14,77],
    [15,83],
    [16,89],
    [17,95],
    [18,101],
    [19,107],
    [20,113],
    [21,119],
    [24,125],
    [32,166],
    [40,207],
    [48,248],
    [56,289],
    [64,330],
    [72,371],
    [80,412],
    [88,453],
    [96,494],
    [104,535],
];

fn entropy_to_pwlen(entropy: usize) -> usize {
    if entropy <= PW_ENTROPY[0][1] {
        PW_ENTROPY[0][0]
    } else {
        for i in 0..(PW_ENTROPY.len()-1) {
            if entropy > PW_ENTROPY[i][1] && entropy <= PW_ENTROPY[i+1][1] {
                return PW_ENTROPY[i+1][0];
            }
        }
        PW_ENTROPY[PW_ENTROPY.len()-1][0]
    }
}

fn uppers_entropy() -> f64 {
    (UPPERS.len() as f64).log2()
}

fn all_letters_entropy() -> f64 {
    (ALL_LETTERS.len() as f64).log2()
}

// check if a password has a number
fn has_num(pw: &[char]) -> bool {
    for c in pw {
        for n in &NUMBERS {
            if c == n {
                return true;
            }
        }
    }
    false
}

// check if a password has a lowercase letter
fn has_lower(pw: &[char]) -> bool {
    for c in pw {
        for cl in &LOWERS {
            if c == cl {
                return true;
            }
        }
    }
    false
}

// check if a password has a special character
fn has_spec(pw: &[char]) -> bool {
    for c in pw {
        if *c == SPEC1 || *c == SPEC2 || *c == SPECSEP {
            return true;
        }
    }
    false
}

// check if a password has a repetition (case insensitive)
fn has_repeat(pw: &[char]) -> bool {
    for i in 1..pw.len() {
        if pw[i].to_lowercase().to_string() == pw[i-1].to_lowercase().to_string() {
            return true;
        }
    }
    false
}

// check if a password has two special characters in a row
fn has_morse(pw: &[char]) -> bool {
    for i in 1..pw.len() {
        if (pw[i] == SPEC1 && pw[i-1] == SPEC2)
            || (pw[i] == SPEC2 && pw[i-1] == SPEC1) {
            return true;
        }
    }
    false
}

// generate a single password character
fn gen_letter(rng: &mut rand::rngs::ThreadRng) -> char {
    let i = rng.gen_range(0..ALL_LETTERS.len());
    ALL_LETTERS[i]
}

// generate an uppercase letter (used for start & finishing letters)
fn gen_upper(rng: &mut rand::rngs::ThreadRng) -> char {
    let i = rng.gen_range(0..UPPERS.len());
    UPPERS[i]
}

// generate a candidate password
fn gen_candidate(rng: &mut rand::rngs::ThreadRng, arr: &mut[char]) {
    arr[0] = gen_upper(rng);
    for i in 1..arr.len()-1 {
        arr[i] = gen_letter(rng);
    }
    arr[arr.len()-1] = gen_upper(rng);

    // put block separator for long passwords
    if arr.len() >= SPECSEP_MINSIZE {
        for i in 1..arr.len()-1 {
            if i % SPECSEP_BLOCKSIZE == 0 {
                arr[i] = SPECSEP;
            }
        }
    }
}

fn candidate_specsep_count(len: usize) -> usize {
    let mut count: usize = 0;
    if len < SPECSEP_MINSIZE {
        return 0;
    }
    for i in 1..(len-1) {
        if i % SPECSEP_BLOCKSIZE == 0 {
            count += 1;
        }
    }
    count
}

fn candidate_entropy(len: usize) -> f64 {
    if len <= 2 {
        uppers_entropy() * (len as f64)
    } else {
        let lettercount = len - 2 - candidate_specsep_count(len);
        uppers_entropy() * 2.0 + all_letters_entropy() * (lettercount as f64)
    }
}

fn pw_entropy(candidate_entropy: f64, candidate_count: usize) -> f64 {
    candidate_entropy - (candidate_count as f64).log2()
}

// generate a good password, returns its entropy
fn pwgen(rng: &mut rand::rngs::ThreadRng, chars: &mut[char]) -> f64 {
    let pwlen = chars.len();
    let candidate_entropy = candidate_entropy(pwlen);
    let mut candidate_count: usize = 0;

    loop {
        gen_candidate(rng, chars);

        candidate_count += 1;

        if !has_num(chars) {
            continue;
        }
        if !has_spec(chars) {
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
        // zxcvbn checks for weak passwords by finding words and other
        // patterns in them and returns a list of those patterns as a
        // 'sequence'. We only accept passwords with a single 'bruteforce'
        // element in the sequence.
        let pws: String = chars.iter().collect();
        let estimate = zxcvbn(&pws, &[]).unwrap();
        if estimate.sequence().len() > 1 {
            continue;
        }
        break;
    }

    pw_entropy(candidate_entropy, candidate_count)
}

fn main() {

    // 1) Declare & Parse command line arguments
    let m = Command::new("gpwg")
        .version("1.0")
        .about("Generates good passwords.")
        .long_about("
This program generates a good password with 18 characters and 100 bits of entropy by default.
Consider using the --copy option to copy it to the clipboard to avoid unintentional leaks.
        ")
        .author("Frédéric van der Essen")
        .arg(
            Arg::new("strong")
                .long("strong")
                .short('s')
                .takes_value(false)
                .help("Generates a strong password with 32 characters and 160 bits of entropy")
                .required(false)
        )
        .arg(
            Arg::new("length")
                .long("length")
                .short('l')
                .takes_value(true)
                .forbid_empty_values(true)
                .help("Sets password length (10-128)")
                .required(false)
        )
        .arg(
            Arg::new("entropy")
                .long("entropy")
                .short('e')
                .takes_value(true)
                .forbid_empty_values(true)
                .help("Sets password entropy in bits (40-512)")
                .required(false)
        )
        .arg(
            Arg::new("copy")
                .long("copy")
                .short('c')
                .takes_value(false)
                .help("Copies the password to clipboard.")
                .required(false)
        )
        .after_help("")
        .get_matches();

    let printout = !m.is_present("copy");

    // 1) Deduct password size based on arguments
    let mut desired_length = if m.is_present("length") {
        m.value_of("length").unwrap().parse::<usize>().unwrap_or(0)
    } else { 0 };

    if m.is_present("entropy") {
        let entropy = m.value_of("entropy").unwrap().parse::<usize>().unwrap_or(0);
        if entropy > 0 {
            desired_length = entropy_to_pwlen(entropy).max(desired_length);
        }
    }
    if m.is_present("strong") {
        desired_length = desired_length.max(STRONG_SIZE);
    }
    if desired_length == 0 {
        desired_length = DEFAULT_SIZE;
    }

    desired_length = desired_length.clamp(MIN_SIZE, MAX_SIZE);

    // 2) Compute password of specified size
    let mut rng = rand::thread_rng();
    let mut pw = vec!['_'; desired_length];
    pwgen(&mut rng, &mut pw);
    let pws: String = pw.iter().collect();

    // 3) Depending on options, either print password or copy it to clipboard
    if printout {
        // 3.1) Output password to stdout
        println!("{}", pws);
    } else {
        // 3.2) Copy password to clipboard
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents(pws).unwrap();
        println!("Generated password sent to the clipboard. Clear & exit with Ctrl-C.");

        // 3.3) Set Ctrl-C handler so that we can interrupt the 30sec timer
        ctrlc::set_handler(move || {
            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
            ctx.set_contents("".to_owned()).unwrap();
            std::process::exit(0);
        }).expect("Error setting Ctrl-C handler");

        // 3.4) Wait 2min then clear password
        let expire = time::Duration::from_secs(120);
        thread::sleep(expire);
        ctx.set_contents("".to_owned()).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_has_num_no() {
        let s: [char; 3] = ['a', 'X', '@'];
        assert_eq!(has_num(&s), false);
    }

    #[test]
    fn test_has_num_yes() {
        let nums: [char; 8] = [
            '2','3','4','5','6','7','8','9'
        ];
        for n in nums {
            let s: [char; 3] = ['a', n, '@'];
            assert!(has_num(&s));
        }
    }

    #[test]
    fn test_has_lower_no() {
        let s: [char; 4] = ['A', 'X', '@', '4'];
        assert_eq!(has_lower(&s), false);
    }

    #[test]
    fn test_has_lower_yes() {
        let s: [char; 5] = ['A', 'X', '@', '4', 'b'];
        assert!(has_lower(&s));
    }

    #[test]
    fn test_has_spec_no() {
        let s: [char; 4] = ['A', 'X', 'a', '4'];
        assert_eq!(has_spec(&s), false);
    }

    #[test]
    fn test_has_spec_at() {
        let s: [char; 5] = ['A', 'X', 'a', '4', '@'];
        assert!(has_spec(&s));
    }

    #[test]
    fn test_has_spec_bang() {
        let s: [char; 5] = ['A', '!', 'a', '4', 'X'];
        assert!(has_spec(&s));
    }

    #[test]
    fn test_has_spec_sep() {
        let s: [char; 5] = ['A', 'X', 'a', '4', '-'];
        assert!(has_spec(&s));
    }

    #[test]
    fn test_has_repeat_empty() {
        let s: [char; 0] = [];
        assert_eq!(has_repeat(&s), false);
    }

    #[test]
    fn test_has_repeat_single() {
        let s: [char; 1] = ['x'];
        assert_eq!(has_repeat(&s), false);
    }

    #[test]
    fn test_has_repeat_no() {
        let s: [char; 2] = ['x','y'];
        assert_eq!(has_repeat(&s), false);
    }

    #[test]
    fn test_has_repeat_no3() {
        let s: [char; 3] = ['x','y','x'];
        assert_eq!(has_repeat(&s), false);
    }

    #[test]
    fn test_has_repeat_yes() {
        let s: [char; 2] = ['y','y'];
        assert!(has_repeat(&s));
    }

    #[test]
    fn test_has_repeat_yes3() {
        let s: [char; 3] = ['!','@','@'];
        assert!(has_repeat(&s));
    }

    #[test]
    fn test_has_morse_empty() {
        let s: [char; 0] = [];
        assert_eq!(has_morse(&s), false);
    }

    #[test]
    fn test_has_morse_no() {
        let s: [char; 4] = ['a','@','b','!'];
        assert_eq!(has_morse(&s), false);
    }

    #[test]
    fn test_has_morse_yes() {
        let s: [char; 4] = ['a', 'b', '@', '!'];
        assert!(has_morse(&s));
        let s: [char; 4] = ['a', '!', '@', 'b'];
        assert!(has_morse(&s));
    }

    #[test]
    fn test_specsep_count() {
        let mut rng = rand::thread_rng();
        for len in MIN_SIZE..MAX_SIZE {
            let specsep_count = candidate_specsep_count(len);
            let mut pw = vec!['_'; len];
            pwgen(&mut rng, &mut pw);
            let mut count: usize = 0;
            for c in pw {
                if c == SPECSEP {
                    count += 1;
                }
            }
            assert_eq!(specsep_count, count);
        }
    }

    #[test]
    fn test_randomness() {
        // generate 10 thousand passwords and check they all differ.
        let len: usize = DEFAULT_SIZE;
        let samples: usize = 10000;
        let mut pwds = HashSet::new();
        let mut rng = rand::thread_rng();
        for _ in 1..samples {
            let mut pw = vec!['_'; len];
            pwgen(&mut rng, &mut pw);
            let pws: String = pw.iter().collect();
            assert!(!pwds.contains(&pws));
            pwds.insert(pws);
        }
    }

    #[test]
    fn test_entropy() {
        let samples: usize = 1000;
        let mut rng = rand::thread_rng();
        for pw_len_entr in PW_ENTROPY {
            let len = pw_len_entr[0];
            let entr = pw_len_entr[1];
            let mut entropy: f64 = 0.0;
            for _ in 1..samples {
                let mut pw = vec!['_'; len];
                entropy += pwgen(&mut rng, &mut pw);
            }
            entropy = entropy / (samples as f64);
            println!("{};{}", len, entropy as i32);
            assert!(entropy >= (entr-1) as f64);
        }
    }

    #[test]
    #[ignore]
    fn test_entropy() {
        // this 'test' is used to generate a list of password length and their entropy
        println!("pw_len;entropy");
        let samples: usize = 1000;
        let mut rng = rand::thread_rng();
        for len in 8..128 {
            let mut entropy: f64 = 0.0;
            for _ in 1..samples {
                let mut pw = vec!['_'; len];
                entropy += pwgen(&mut rng, &mut pw);
            }
            entropy = entropy / (samples as f64);
            println!("{};{}", len, entropy as i32);
        }
    }
}

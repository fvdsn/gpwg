use rand::Rng;
use clap::{Arg, Command};
use zxcvbn::zxcvbn;
use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;
use std::{thread, time};

// Constants that control the shape of the generated password
const WEAK_SIZE: usize = 10;
const STRONG_SIZE: usize = 32;
const DEFAULT_SIZE: usize = 18;
const MAX_SIZE: usize = 128;

// The two special characters
//  - accepted by most password restrictions
//  - on first screen of iphone keyboard
//  - available on most keyboards
//  - rarely need to be escaped
const SPEC1: char = '!';
const SPEC2: char = '@';

// Block separator for long passwords
const SPECSEP: char = '-';

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
}

// generate a candidate password with '-' separated blocks
fn gen_big_candidate(rng: &mut rand::rngs::ThreadRng, arr: &mut[char]) {
    gen_candidate(rng, arr);
    for i in 1..arr.len()-1 {
        if i % 8 == 0 {
            arr[i] = SPECSEP;
        }
    }
}

// generate a good password
fn pwgen(rng: &mut rand::rngs::ThreadRng, chars: &mut[char]) {
    let strong = chars.len() >= STRONG_SIZE;
    loop {
        if strong {
            gen_big_candidate(rng, chars);
        } else {
            gen_candidate(rng, chars);
        }
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
}

fn main() {

    // 1) Declare & Parse command line arguments
    let m = Command::new("gpwg")
        .version("1.0")
        .about("Generates a good password and copies it to the clipboard.")
        .long_about("
Generates a good password and prints it to stdout.

Consider using the --copy option to copy it to the clipboard 
to avoid leaking it unintentionally.

The --strong, --weak, --default, --length=N options control the
length and thus strength of the password.
        ")
        .author("Frédéric van der Essen")
        .arg(
            Arg::new("weak")
                .long("weak")
                .short('w')
                .takes_value(false)
                .help("10 characters, 54bit of entropy")
                .required(false)
        )
        .arg(
            Arg::new("strong")
                .long("strong")
                .short('s')
                .takes_value(false)
                .help("32 characters, 160bit of entropy")
                .required(false)
        )
        .arg(
            Arg::new("default")
                .long("default")
                .short('d')
                .takes_value(false)
                .help("18 characters, 100bit of entropy")
                .required(false)
        )
        .arg(
            Arg::new("length")
                .long("length")
                .short('l')
                .takes_value(true)
                .forbid_empty_values(true)
                .help("Sets password length [10, 128]")
                .required(false)
        )
        .arg(
            Arg::new("copy")
                .long("copy")
                .short('c')
                .takes_value(false)
                .help("Copy the password to clipboard.")
                .required(false)
        )
        .after_help("")
        .get_matches();

    let printout = !m.is_present("copy");
    let length = if m.is_present("length") {
        m.value_of("length").unwrap().parse::<usize>().unwrap_or(0)
    } else { 0 };
    let strong = m.is_present("strong");
    let default = !strong && m.is_present("default");
    let weak = !default && m.is_present("weak");

    // 2) Compute password size based on supplied arguments
    let size = if length > 0 { length.clamp(WEAK_SIZE, MAX_SIZE) }
       else if strong { STRONG_SIZE }
       else if weak { WEAK_SIZE }
       else { DEFAULT_SIZE };

    let qualifier = if length > 0 { format!("({length}) ") }
        else if strong { "(strong) ".to_owned() }
        else if weak { "(weak) ".to_owned() }
        else if default { "(default)".to_owned() }
        else { "".to_owned() };
    
    // 3) Compute password of specified size
    let mut rng = rand::thread_rng();
    let mut pw = vec!['_'; size];
    pwgen(&mut rng, &mut pw);
    let pws: String = pw.iter().collect();

    // 4) Depending on options, either print password or copy it to clipboard
    if printout {
        // 4.1) Output password to stdout
        println!("{}", pws);
    } else {
        // 4.2) Copy password to clipboard
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents(pws).unwrap();
        println!("Generated password {}sent to the clipboard. Clear & exit with Ctrl-C.", qualifier);

        // 4.3) Set Ctrl-C handler so that we can interrupt the 30sec timer
        ctrlc::set_handler(move || {
            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
            ctx.set_contents("".to_owned()).unwrap();
            std::process::exit(0);
        }).expect("Error setting Ctrl-C handler");

        // 4.4) Wait 30sec then clear password
        let expire = time::Duration::from_secs(120);
        thread::sleep(expire);
        ctx.set_contents("".to_owned()).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

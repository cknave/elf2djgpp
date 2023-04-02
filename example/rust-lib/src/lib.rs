#![feature(c_size_t)]
#![feature(lang_items)]
#![no_std]
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::{c_char, c_void, CStr};
use core::fmt::{Display, Formatter};
use core::str::{from_utf8, FromStr};

//
// Rust/DJGPP interoperability
//

// Our C API: we'll use DJGPP's `memalign` and `free` for the allocator, and our own `input`
// and `output` from example.c to communicate with the user.
mod c_api {
    use core::ffi::{c_char, c_size_t, c_void};
    extern "C" {
        pub fn memalign(align: c_size_t, amt: c_size_t) -> *mut c_void;
        pub fn free(ptr: *mut c_void);
        pub fn input(prompt: *const c_char) -> *mut c_char;
        pub fn output(s: *const c_char);
    }
}

// Create wrappers around our unsafe C code
fn input(prompt: &str) -> InputString {
    unsafe {
        let ptr = c_api::input(prompt.as_ptr() as *mut c_char);
        InputString::from_ptr(ptr)
    }
}

fn output(s: &str) {
    unsafe { c_api::output(s.as_ptr() as *const c_char) }
}

// Let's write a little wrapper around CStr to let Rust free our string when it's done.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct InputString<'a> {
    pub c_str: &'a CStr,
}

impl<'a> InputString<'a> {
    fn from_ptr(ptr: *mut c_char) -> Self {
        unsafe {
            Self {
                c_str: CStr::from_ptr(ptr),
            }
        }
    }
}

impl<'a> Drop for InputString<'a> {
    fn drop(&mut self) {
        unsafe {
            output(format!("    (freeing \"{self}\")\n\0").as_str());
            c_api::free(self.c_str.as_ptr() as *mut c_void);
        }
    }
}

impl<'a> Display for InputString<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.c_str.to_bytes().escape_ascii())
    }
}

//
// DJGPP global allocator
//

// Create a new allocator, `DJGPPAllocator`, to allocate and free memory using DJGPP.
pub struct DJGPPAllocator;

unsafe impl GlobalAlloc for DJGPPAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        c_api::memalign(layout.align(), layout.size()) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        c_api::free(ptr as *mut c_void)
    }
}

#[global_allocator]
static GLOBAL: DJGPPAllocator = DJGPPAllocator;

//
// Example program
//

// And here's our example program. We'll use several containers that allocate memory on the
// heap to use our DJGPP allocator.
#[no_mangle]
pub extern "C" fn run_rust_example() {
    // Don't forget to add null terminators if your C API requires them!
    output("Integer Organizer: A Rust and DJGPP Example Program\n\n\0");
    output("Enter the name of a collection, then when prompted, a comma-separated list of\n\0");
    output("integers.  Enter an empty line when you're done!\n\n\0");

    let mut collections: BTreeMap<InputString, Vec<i32>> = BTreeMap::new();

    loop {
        let colname = input("Enter a collection name:\n> \0");
        if colname.c_str.to_bytes().is_empty() {
            break;
        }
        let collection = collections.entry(colname).or_insert(Vec::new());

        let ints_str = input("And what integers would you like to add?\n> \0");
        if ints_str.c_str.to_bytes().is_empty() {
            break;
        }
        let items = ints_str.c_str.to_bytes().split(|c| *c == b',');
        for (index, item_slice) in items.enumerate() {
            match from_utf8(item_slice).map(i32::from_str) {
                Ok(Ok(val)) => {
                    collection.push(val);
                    output(format!("Added {val}\n\0").as_str());
                }
                _ => {
                    output(format!("I couldn't parse item {0}\n\0", index + 1).as_str());
                }
            }
        }
    }

    output("I've sorted your integers for you.  Here you are:\n\0");
    for (colname, mut ints) in collections {
        output(format!("{colname}: \0").as_str());
        ints.sort();
        let mut separator = "";
        for int in ints {
            output(format!("{separator}{int}\0").as_str());
            separator = ", ";
        }
        output("\n\0");
    }
}

//
// Cruft
//

// And here's some obligatory no_std things:
// For panic, just loop forever.
#[cfg(not(test))]
#[panic_handler]
fn panic(_panic: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

// And I have no idea what this is but Rust really wants it to exist.
#[cfg(not(test))]
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

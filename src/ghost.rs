mod timberwolf;

extern crate libc;

#[macro_use]
extern crate redhook;

#[macro_use]
extern crate lazy_static;

extern crate errno;


use libc::{sockaddr, socklen_t, c_int, c_char, mode_t, size_t, DIR, FILE, ssize_t};
use std::ffi::{CStr};
use std::{fs, str};
use reqwest;
use url::{Url};
use chrono::Local;
use std::{env, ptr};
use sysinfo::{System,SystemExt, ProcessExt};
use users::{get_user_by_uid, get_current_uid};
use errno::{Errno, set_errno};


use timberwolf::{Policy, get_aws_info, AwsFunctionInfo, Event};

lazy_static! {
    static ref POLICY: Policy = parse_policy();
    static ref FUNCTION_INFO: AwsFunctionInfo = get_aws_info();
}



hook! {
    unsafe fn access(pathname: *const c_char, mode: c_int) -> c_int => ghost_access{
        log::debug!("IN ACCESS");
        let c_str = CStr::from_ptr(pathname as *const i8);
        let path = c_str.to_str().unwrap();
        log::debug!("FILEPATH {:?}", path);

         if !allow_filesystem_access(path){
            log::debug!("BACK FROM ALLOW FS ACCESS");
            create_log("BLOCK", &*format!("read_write_tmp policy enforced for {}", path));
            send_event("block", &*format!("read_write_tmp policy enforced for {}", path), path, "read_write_tmp");
            set_errno(Errno{0:13});
            return -1;
        }

        real!(access)(pathname, mode)
    }
}

//ssize_t write(int fd, const void *buf, size_t count);
/*
hook!{
    unsafe fn write(fd: c_int, buf: *mut libc::c_void, count: size_t) -> ssize_t => ghost_write{
        log::debug!("IN WRITE");
        //let f = File::from_raw_fd(fd);
        //log::debug!("FILE DETAILS {:?}", f.metadata());
        real!(write)(fd, buf, count)
    }
}
*/

hook! {
    unsafe fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int) -> c_int => ghost_openat{
        log::debug!("IN OPEN AT");
        let c_str = CStr::from_ptr(pathname as *const i8);
        let path = c_str.to_str().unwrap();
        log::debug!("PATHNAME {:?}", path);
        real!(openat)(dirfd, pathname, flags)
    }
}

hook! {
    unsafe fn execve(pathname: *const c_char, argv: *const c_char, envp: *const c_char) -> c_int => ghost_execve{
        log::debug!("IN EXECVE");
        let c_str = CStr::from_ptr(pathname as *const i8);
        let path = c_str.to_str().unwrap();
        log::debug!("PATHNAME {:?}", path);
        real!(execve)(pathname, argv, envp)
    }
}

hook! {
    unsafe fn open(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => ghost_open{
        log::debug!("IN OPEN");

        let c_str = CStr::from_ptr(pathname as *const i8);
        let path = c_str.to_str().unwrap();
        log::debug!("PATHNAME {:?}", path);
        log::debug!("FLAGS {:?}", flags);

         if !allow_filesystem_access(path){
            log::debug!("BACK FROM ALLOW FS ACCESS");
            //create_log("BLOCK", &*format!("read_write_tmp policy enforced for {}", path));
            //send_event("block", &*format!("read_write_tmp policy enforced for {}", path), path, "read_write_tmp");
            set_errno(Errno{0:13});
            log::debug!("BACK FROM SEND EVENT -----------------------");
            return -1;
        }

        real!(open)(pathname, flags, mode)
    }
}


/*
hook! {
    unsafe fn open64(pathname: *const c_char, mode: usize) -> *mut FILE => ghost_open64 {
        log::debug!("IN F-OPEN");
        let c_str = CStr::from_ptr(pathname as *const i8);
        let path = c_str.to_str().unwrap();
        log::debug!("PATHNAME {:?}", path);
        real!(open64)(pathname, mode)

    }
}
*/
//int utimes(const char *filename, const struct timeval times[2]);

hook! {
    unsafe fn utimes(filename: *const c_char, times: *const libc::timeval) -> c_int => ghost_utimes {
        log::debug!("IN UTIMES");
        let c_str = CStr::from_ptr(filename as *const i8);
        let file_name = c_str.to_str().unwrap();
        log::debug!("FileName {:?}", file_name);
        real!(utimes)(filename, times)

    }
}


hook! {
    unsafe fn fopen(pathname: *const c_char, mode: usize) -> usize => ghost_fopen {
        log::debug!("IN OPEN64");
        let c_str = CStr::from_ptr(pathname as *const i8);
        let path = c_str.to_str().unwrap();
        log::debug!("PATHNAME {:?}", path);
        real!(fopen)(pathname, mode)

    }
}


hook! {
    unsafe fn opendir(name: *const c_char) -> *mut DIR => ghost_opendir{
        log::debug!("IN OPENDIR");
        let c_str = CStr::from_ptr(name as *const i8);
        let path = c_str.to_str().unwrap();
        log::debug!("NAME {:?}", path);


        if !allow_filesystem_access(path){
            log::debug!("BACK FROM ALLOW FS ACCESS");
            //let test = ptr::NonNull::<libc::DIR>::;
            create_log("BLOCK", &*format!("read_write_tmp policy enforced for {}", path));
            send_event("block", &*format!("read_write_tmp policy enforced for {}", path), path, "read_write_tmp");
            let p: *mut DIR = ptr::null_mut();
            set_errno(Errno{0:13});
            return p;

        }

        real!(opendir)(name)
    }
}
/*
hook! {
    unsafe fn read(fd: c_int, buf: *mut libc::c_void, count: size_t) -> size_t => ghost_read{
        log::debug!("IN READ");
        //println!("BUF DATA: {:?}", *buf);
        //let mut buf2 = vec!(1,2,3);
        //let data2 = buf2.as_mut_ptr() as *mut c_void;
        //println!("DATA2: {:?}", data2);
        real!(read)(fd, buf, count)
    }
}
*/
hook!{
      unsafe fn connect(sockfd: c_int, addr: *mut sockaddr, addrlen: socklen_t) -> c_int => t_connect {
        //println!("\nIN CONNECT: \n");
        //println!("YOYO: {:?}", *POLICY);
        //let rust_socket: SocketAddr = &addr;
        //let sock_in: &sockaddr_in;
        //sock_in = &*(addr as *const sockaddr_in);
        //print_type_of(&sock_in);
        //let test: *sockaddr_in = &addr;
        //let addr2 = Ipv4Addr::from (sock_in.sin_addr.s_addr);
        //println!("FAMILY: {}", i32::from(sock_in.sin_family) == libc::AF_INET);
        //println!("ADDR: {}\n", addr2);
        real!(connect)(sockfd, addr, addrlen)
    }
}

hook!{
    unsafe fn getaddrinfo(node: *const char, service: *const char, hints: *const libc::addrinfo, res: *mut *mut libc::addrinfo) -> c_int => t_getaddrinfo{
        //println!("IN GETADDR");
        log::debug!("[GHOST ACTION]: In GETADDR");
        let c_str = CStr::from_ptr(node as *const i8);
        let address = c_str.to_str().unwrap();
        //println!("PARSE 1 complete: {:?}", service);



        if !service.is_null(){
           // let c_str2 = CStr::from_ptr(service as *const i8);
            //let service2 = c_str2.to_str().unwrap_or("service 2 not here");
            //println!("IN GETADDRINFO SERVICE: {:?}\n", service2);
        }

        //println!("PARSE 2 complete");
        log::debug!("IN GETADDRINFO NODE: {}\n", address);
        //println!("IN GETADDRINFO HINTS FLAGS: {:?}\n", (*hints).ai_flags);
        //println!("IN GETADDRINFO HINTS FAMILY: {}\n", (*hints).ai_family);
       // println!("IN GETADDRINFO HINTS SOCKTYPE: {}\n", (*hints).ai_socktype);


        if !allow_outbound_connection(address){
            set_errno(Errno{0:13});
            return -2
        }else{
            real!(getaddrinfo)(node, service, hints, res)
        }
    }
}


fn allow_outbound_connection(addr: &str) -> bool {
    log::debug!("IN OUTBOUND CONNECTION");
    let found = POLICY.outbound_connectivity.exceptions.iter().any(|exception_addr| addr.contains(exception_addr) );
    let action: String = POLICY.outbound_connectivity.action.clone();

    if (action == "block" && found) ||  (action != "block" && !found){
        if action == "block" {
            create_log("ALLOW", &*format!("policy exception for {}", addr));
            send_event("allow", &*format!("policy exception for {}", addr), addr,"network");
        }

        if action != "block" { create_log("ALLOW", &*format!("policy allowed for {}", addr)); }
        return true
    }else{
        if action != "block" { create_log("BLOCK", &*format!("policy exception for {}", addr)); }
        if action == "block" {
            create_log("BLOCK", &*format!("policy enforced for {}", addr));
            send_event("block", &*format!("policy enforced for {}", addr), addr,"network");
        }
        return false
    }

}


fn allow_filesystem_access(path: &str) -> bool {

    if POLICY.read_write_tmp == "block"{
        log::debug!("IN ALLOW FILESYSTEM ACCESS {}", path);
        if path.contains("tmp"){
            log::debug!("path does contain tmp");
            return false
        }
    }

    return true


}

/*
fn print_type_of<T>(_: &T) {

    println!("{}", std::any::type_name::<T>())
}
*/


fn parse_policy() -> Policy{

   // println!("IN PARSE POLICY");
   // println!("Listing all env vars:");
   // for (key, val) in env::vars() {
   //     println!("{}: {}", key, val);
   // }

    let policy_path = env::var("GHOST_POLICY").expect("GHOST [ERROR] GHOST_POLICY env not found");

    timberwolf::setup_logging();

    let policy_json = fs::read_to_string(policy_path)
        .expect("ERROR: policy.json file not found.");

    let mut policy: Policy = serde_json::from_str(&policy_json).unwrap();
    let api = Url::parse(&*policy.api_endpoint.clone()).unwrap();
    let host = api.host().unwrap();
    policy.outbound_connectivity.exceptions.push(host.to_string());
    policy.outbound_connectivity.exceptions.push("127.0.0.1".to_string());
    policy.outbound_connectivity.exceptions.push("0.0.0.0".to_string());
    policy.api_endpoint = api.to_string();

    return policy
}



fn create_log(action: &str, msg: &str){
    log::debug!("[GHOST ACTION]: {} -> {}", action, msg);
}

fn send_event(action: &str, msg: &str, what: &str, event_type: &str) {
    log::debug!("IN SEND_EVENT");


    let system = System::new_all();
    let current_process_id = sysinfo::get_current_pid().unwrap();
    let current_process = system.process(current_process_id).unwrap();
    let user = get_user_by_uid(get_current_uid()).unwrap();


    let event = Event{
        aws_function_info: FUNCTION_INFO.clone(),
        event_type: event_type.to_string(),
        action: action.to_string(),
        what: what.to_string(),
        message:msg.to_string(),
        time: Local::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
        process_id: current_process_id.to_string(),
        process_name: current_process.name().to_string(),
        process_command: current_process.cmd().join(","),
        user_id: user.uid().to_string(),
        user_name: String::from(user.name().to_str().unwrap())
    };

    //let json_string = serde_json::to_string(&event).unwrap();
    let api = POLICY.api_endpoint.clone();
    //println!("IN SEND EVENT {} to {}", json_string, api);

    //println!("ENDPOINT: {}", &*api);
    let client = reqwest::blocking::Client::new();
    match client.post(&*api).json(&event).send(){
        Err(e) => handler(e),
        Ok(_v) => {},
    }


}


fn handler(e: reqwest::Error){
    //print!("IN ERROR Handler");
    //print_type_of(&e);
    if e.is_request() {
        //print!("IN ERROR REQUEST");
        match e.url(){
            None => log::debug!("No Url given"),
            Some(url) => log::debug!("Problem making request to: {}", url),
        }
    }
    if e.is_redirect() {
        log::debug!("server redirecting too many times or making loop");
    }
}
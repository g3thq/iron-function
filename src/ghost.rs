mod timberwolf;

extern crate libc;

#[macro_use]
extern crate redhook;

#[macro_use]
extern crate lazy_static;



use libc::{sockaddr, socklen_t, c_int, sockaddr_in, c_uint, mmsghdr, c_char, mode_t};
use std::ffi::CStr;
use std::path::Path;
use std::{fs, str};
use reqwest;
use url::{Url};
use chrono::Local;
use std::env;
use sysinfo::{System, get_current_pid, SystemExt, ProcessExt};
use users::{get_user_by_uid, get_current_uid};

use timberwolf::{Policy, get_aws_info, AwsFunctionInfo, Event};

lazy_static! {
    static ref POLICY: Policy = parse_policy();
    static ref FUNCTION_INFO: AwsFunctionInfo = get_aws_info();
}


hook!{
    unsafe fn sendmmsg(sockfd: c_int, msgvec: *mut mmsghdr, vlen: c_uint, flags: c_int) -> c_int => ghost_sendmmsg {
        //println!("IN SENDMMSG");
        real!(sendmmsg)(sockfd, msgvec, vlen, flags)
    }
}

hook! {
    unsafe fn stat(pathname: *const c_char, statbuf: *const libc::stat) -> c_int => ghost_stat{
        println!("IN STAT");
        println!("FILEPATH {:?}", pathname);
        real!(stat)(pathname, statbuf)
    }
}

hook! {
    unsafe fn open(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => ghost_open{
        println!("IN OPEN");
        let c_str = CStr::from_ptr(pathname as *const i8);
        let path = c_str.to_str().unwrap();
        println!("PATHNAME {:?}", path);
        println!("FLAGS {:?}", flags);
        real!(open)(pathname, flags, mode)
    }
}

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
        log::info!("[GHOST ACTION]: In GETADDR");
        let c_str = CStr::from_ptr(node as *const i8);
        let address = c_str.to_str().unwrap();
        //println!("PARSE 1 complete: {:?}", service);



        if !service.is_null(){
           // let c_str2 = CStr::from_ptr(service as *const i8);
            //let service2 = c_str2.to_str().unwrap_or("service 2 not here");
            //println!("IN GETADDRINFO SERVICE: {:?}\n", service2);
        }

        //println!("PARSE 2 complete");
        println!("IN GETADDRINFO NODE: {}\n", address);
        //println!("IN GETADDRINFO HINTS FLAGS: {:?}\n", (*hints).ai_flags);
        //println!("IN GETADDRINFO HINTS FAMILY: {}\n", (*hints).ai_family);
       // println!("IN GETADDRINFO HINTS SOCKTYPE: {}\n", (*hints).ai_socktype);


        if !allow_outbound_connection(address){
            return 1
        }else{
            real!(getaddrinfo)(node, service, hints, res)
        }
    }
}


fn allow_outbound_connection(addr: &str) -> bool {
    println!("IN OUTBOUND CONNECTION");
    let found = POLICY.outbound_connectivity.exceptions.iter().any(|exception_addr| addr.contains(exception_addr) );
    let action: String = POLICY.outbound_connectivity.action.clone();
    println!("IN OUTBOUND CONNECTION2");

    if (action == "block" && found) ||  (action != "block" && !found){
        if action == "block" {
            create_log("ALLOW", &*format!("policy exception for {}", addr));
            //send_event("allow", &*format!("policy exception for {}", addr), "network");
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


fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}



fn parse_policy() -> Policy{

    println!("IN PARSE POLICY");
    println!("Listing all env vars:");
    for (key, val) in env::vars() {
        println!("{}: {}", key, val);
    }

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
    log::info!("[GHOST ACTION]: {} -> {}", action, msg);
}

fn send_event(action: &str, msg: &str, what: &str, event_type: &str) {
    println!("IN Send EVENT");


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
        Ok(v) => {},
    }


}


fn handler(e: reqwest::Error){
    //print!("IN ERROR Handler");
    print_type_of(&e);
    if e.is_request() {
        //print!("IN ERROR REQUEST");
        match e.url(){
            None => println!("No Url given"),
            Some(url) => println!("Problem making request to: {}", url),
        }
    }
    if e.is_redirect() {
        println!("server redirecting too many times or making loop");
    }
}
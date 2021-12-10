use serde::{Serialize, Deserialize};
use std::env;

use chrono::Local;
use std::io::Write;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AwsFunctionInfo {
    pub region: String,
    pub execution_env: String,
    pub lambda_function_name: String,
    pub initialization_type: String,
    pub task_root: String,
    pub runtime_dir: String,
    pub tz: String,
    pub version: String,
    pub memory_size: String,
    pub log_group: String,
    pub log_stream: String
}

pub fn get_aws_info() -> AwsFunctionInfo{

    let region = env::var("AWS_REGION").unwrap_or("none".to_string());
    let exec_env = env::var("AWS_EXECUTION_ENV").unwrap_or("none".to_string());
    let function_name = env::var("AWS_LAMBDA_FUNCTION_NAME").unwrap_or("none".to_string());
    let init_type = env::var("AWS_LAMBDA_INITIALIZATION_TYPE").unwrap_or("none".to_string());
    let task_root = env::var("LAMBDA_TASK_ROOT").unwrap_or("none".to_string());
    let runtime_directory = env::var("LAMBDA_RUNTIME_DIR").unwrap_or("none".to_string());
    let time_zone = env::var("TZ").unwrap_or("none".to_string());
    let version = env::var("AWS_LAMBDA_FUNCTION_VERSION").unwrap_or("none".to_string());
    let memory_size = env::var("AWS_LAMBDA_FUNCTION_MEMORY_SIZE").unwrap_or("none".to_string());


    let log_group = env::var("AWS_LAMBDA_LOG_GROUP_NAME").unwrap_or("none".to_string());
    let log_stream = env::var("AWS_LAMBDA_LOG_STREAM_NAME").unwrap_or("none".to_string());

    let function_info = AwsFunctionInfo{
        region: region,
        execution_env: exec_env,
        lambda_function_name: function_name,
        initialization_type: init_type,
        task_root: task_root,
        runtime_dir: runtime_directory,
        tz: time_zone,
        version: version,
        memory_size: memory_size,
        log_group: log_group,
        log_stream: log_stream
    };

    log::debug!("FUNCTION INFO: {:?}", function_info);
    return function_info
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Outbound{
    pub action: String,
    pub exceptions: Vec<String>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Policy{
    pub outbound_connectivity: Outbound,
    pub read_write_tmp: String,
    create_child_process: String,
    read_handler: String,
    pub api_endpoint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Event{
    pub aws_function_info: AwsFunctionInfo,
    pub event_type: String,
    pub action: String,
    pub what: String,
    pub message: String,
    pub time: String,
    pub process_id: String,
    pub process_name: String,
    pub process_command: String,
    pub user_id: String,
    pub user_name: String

}


pub fn setup_logging(){

    env_logger::builder()
        .format(|buf, record| {
            writeln!(buf,
                     "{} [{}] - {}",
                     Local::now().format("%Y-%m-%dT%H:%M:%S"),
                     record.level(),
                     record.args()
            )
        })
        .init();
}


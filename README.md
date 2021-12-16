Iron Function is a research project in the areas of serverless runtime detection and prevention of malicious attack vectors. Contributions welcome.

STATUS: Experimental - not ready for use.

###Features
* disable read/write to /tmp dir
* disable read access to function source code
* block/detect outboud network connections
* disable child process spawning

###Approach
There are a few approaches to runtime function protection such as ptrace, LD_PRELOAD, or language specific library.

For our initial POC ghost has decided to try LD_PRELOAD for performance and easy of deployment as a lambda layer. No source code changes are needed or disruption to developer workflow.

###Installation

1. Create function policy see below
2. Build layer including policy file and lib_iron_function.so shared library. (Layer builder in the works)
3. Upload zip as lambda layer and attach to function
4. Specify LD_PRELOAD and IRON_FUNCTION_POLICY env variables
5. Optional: set RUST_LOG=debug to see Iron Function logging in CloudWatch

###Policy File

```
{
  "outbound_connectivity": {
    "action": "block",
    "exceptions": ["aws", "yahoo.com", "37.130.156.31"]
  },
  "read_write_tmp": "block",
  "create_child_process": "block",
  "read_handler": "block",
  "api_endpoint": "https://your_optional_endpoint_to_receive_events"
}
```

###Build from source
RUSTFLAGS="-C target-feature=-crt-static" cargo build

###Docker Image Used for dev/test
amazonlinux:2018.03.0.20180827-with-sources

###Roadmap
* vulnerablity scanning. Source and against running functions.
* secrets detection.
* docs site.




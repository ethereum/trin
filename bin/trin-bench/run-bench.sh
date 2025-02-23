#!/bin/bash

# Define log directories
LOG_DIR="logs"
PAST_RUNS_DIR="$LOG_DIR/past_runs"
mkdir -p "$PAST_RUNS_DIR"

# Create data directories for portal client instances
DATA_DIR_SENDER="data_sender"
DATA_DIR_RECEIVER="data_receiver"
mkdir -p "$LOG_DIR/$DATA_DIR_SENDER" "$LOG_DIR/$DATA_DIR_RECEIVER"

# Check first argument: portal client selection
PORTAL_CLIENT="$1"
VALID_CLIENTS=("trin" "fluffy" "shisui" "ultralight" "samba")
if [[ ! " ${VALID_CLIENTS[@]} " =~ " $PORTAL_CLIENT " ]]; then
    echo "Error: Invalid portal client specified. Choose from: ${VALID_CLIENTS[*]}"
    exit 1
fi

# Check second argument: perf flag
USE_PERF=false
if [ "$2" == "perf" ]; then
    USE_PERF=true
fi

# Clone portal-accumulators repository if not already present
if [ ! -d "../../portal-accumulators" ]; then
    git clone https://github.com/ethereum/portal-accumulators ../../portal-accumulators || { echo "Failed to clone portal-accumulators"; exit 1; }
fi

# Build trin-benchmark-coordinator with release profile
pushd ../.. || { echo "Failed to change directory"; exit 1; }
cargo build --release -p trin-bench || { echo "Failed to build trin-benchmark-coordinator"; exit 1; }
popd || { echo "Failed to return to original directory"; exit 1; }

if [ "$PORTAL_CLIENT" == "trin" ]; then
    pushd ../.. || { echo "Failed to change directory"; exit 1; }
    cargo build --profile profiling -p trin || { echo "Failed to build trin"; exit 1; }
    popd || { echo "Failed to return to original directory"; exit 1; }
fi

# Define process PIDs
PIDS=()

# Find available ports dynamically and ensure they are unique
find_unused_port() {
    local port=$1
    while ss -tuln | awk '{print $4}' | grep -q ":$port$"; do
        port=$((port + 1))
    done
    echo $port
}

PORT_SENDER=$(find_unused_port 9050)
PORT_RECEIVER=$(find_unused_port $((PORT_SENDER + 10)))
EXT_PORT_SENDER=$(find_unused_port 9100)
EXT_PORT_RECEIVER=$(find_unused_port $((EXT_PORT_SENDER + 10)))

# Check if perf flag is passed
USE_PERF=false
if [ "$1" == "perf" ]; then
    USE_PERF=true
fi

run_trin() {
    local log_file="$1"
    local web3_address="$2"
    local external_address="$3"
    local discovery_port="$4"
    local data_dir="$5"
    local mb="$6"
    
    if $USE_PERF; then
        cargo flamegraph --profile release -c "record -F 97 --call-graph dwarf,64000 -g -o $log_file.perf" --release --output "$log_file.svg" -p trin -- \
            --web3-transport http \
            --web3-http-address "$web3_address" \
            --mb "$mb" \
            --bootnodes none \
            --external-address "$external_address" \
            --discovery-port "$discovery_port" \
            --data-dir "$data_dir" \
            --max-radius 100 \            
            > "$log_file.log" 2>&1 &
    else
        # RUST_LOG=info,utp_rs=trace 
        # samply record -s -o $log_file.json.gz -- 
        # TOKIO_CONSOLE_BUFFER_CAPACITY=2000000 TRACING_CONSOLE_PORT=5554 
        samply record -s -o $log_file.json.gz -- ./../../target/profiling/trin \
            --web3-transport http \
            --web3-http-address "$web3_address" \
            --mb "$mb" \
            --bootnodes none \
            --external-address "$external_address" \
            --discovery-port "$discovery_port" \
            --data-dir "$data_dir" \
            --max-radius 100 \
            > "$log_file.log" 2>&1 &
    fi
    PIDS+=("$!")
}

run_trinr() {
    local log_file="$1"
    local web3_address="$2"
    local external_address="$3"
    local discovery_port="$4"
    local data_dir="$5"
    local mb="$6"
    
    if $USE_PERF; then
        cargo flamegraph --profile release -c "record -F 97 --call-graph dwarf,64000 -g -o $log_file.perf" --release --output "$log_file.svg" -p trin -- \
            --web3-transport http \
            --web3-http-address "$web3_address" \
            --mb "$mb" \
            --bootnodes none \
            --external-address "$external_address" \
            --discovery-port "$discovery_port" \
            --data-dir "$data_dir" \
            --max-radius 100 \            
            > "$log_file.log" 2>&1 &
    else
        # RUST_LOG=info,utp_rs=trace 
        # samply record -s -o $log_file.json.gz -- 
        # TOKIO_CONSOLE_BUFFER_CAPACITY=2000000 TRACING_CONSOLE_PORT=5555 
        samply record -s -o $log_file.json.gz -- ./../../target/profiling/trin \
            --web3-transport http \
            --web3-http-address "$web3_address" \
            --mb "$mb" \
            --bootnodes none \
            --external-address "$external_address" \
            --discovery-port "$discovery_port" \
            --data-dir "$data_dir" \
            --max-radius 100 --enable-metrics-with-url 0.0.0.0:9100  \
            > "$log_file.log" 2>&1 &
    fi
    PIDS+=("$!")
}

if [ "$PORTAL_CLIENT" == "trin" ]; then
    # Run trin sender
    run_trin "$LOG_DIR/$DATA_DIR_SENDER" "http://127.0.0.1:$PORT_SENDER/" "127.0.0.1:$EXT_PORT_SENDER" "$EXT_PORT_SENDER" "$LOG_DIR/$DATA_DIR_SENDER" "0"

    # Run trin receiver
    run_trinr "$LOG_DIR/$DATA_DIR_RECEIVER" "http://127.0.0.1:$PORT_RECEIVER/" "127.0.0.1:$EXT_PORT_RECEIVER" "$EXT_PORT_RECEIVER" "$LOG_DIR/$DATA_DIR_RECEIVER" "10000"
fi

# Run trin benchmark coordinator
../../target/release/trin-bench \
    --web3-http-address-node-1 http://127.0.0.1:$PORT_SENDER/ \
    --web3-http-address-node-2 http://127.0.0.1:$PORT_RECEIVER/ \
    --epoch-accumulator-path ../../portal-accumulators \
    --start-era1 1000 \
    --end-era1 1010 \
    --offer-concurrency 10 \
    > "$LOG_DIR/trin_benchmark.log" 2>&1 &
TRIN_BENCH_PID=$!

echo "Started Benchmark"

CLEANED_UP=false
cleanup() {
    if $CLEANED_UP; then
        return
    fi
    CLEANED_UP=true
    echo "Finished benchmark. Stopping processes..."
    
    for PID in "${PIDS[@]}"; do
        if kill -0 "$PID" 2>/dev/null; then
            echo "Killing process with PID $PID..."
            kill -SIGINT "$PID"
            pkill -SIGINT -P "$PID"
        fi
    done
    
    for PID in "${PIDS[@]}"; do
        if kill -0 "$PID" 2>/dev/null; then
            echo "Waiting process with PID $PID..."
            wait "$PID" 2>/dev/null
        fi
    done
    
    if kill -0 "$TRIN_BENCH_PID" 2>/dev/null; then
        echo "Stopping trin-bench with PID $TRIN_BENCH_PID..."
        kill -SIGINT "$TRIN_BENCH_PID"
        pkill -SIGINT -P "$TRIN_BENCH_PID"
        wait "$TRIN_BENCH_PID" 2>/dev/null
    fi

    echo "All processes stopped."
    rm -rf "$LOG_DIR/$DATA_DIR_SENDER" "$LOG_DIR/$DATA_DIR_RECEIVER" "$LOG_DIR/$DATA_DIR_SENDER.perf" "$LOG_DIR/$DATA_DIR_RECEIVER.perf"

    # Generate timestamp-based folder name
    TIMESTAMP=$(date +%s)
    PERF_TAG=$([ "$USE_PERF" == true ] && echo "_perf" || echo "")
    RUN_FOLDER="$PAST_RUNS_DIR/${TIMESTAMP}_${PORTAL_CLIENT}${PERF_TAG}"
    mkdir -p "$RUN_FOLDER"

    # Move logs and performance files to the archive folder
    find "$LOG_DIR" -maxdepth 1 -type f -name "*.log" -exec mv {} "$RUN_FOLDER/" \;
    find "$LOG_DIR" -maxdepth 1 -type f -name "*.svg" -exec mv {} "$RUN_FOLDER/" \;
    find "$LOG_DIR" -maxdepth 1 -type f -name "*.gz" -exec mv {} "$RUN_FOLDER/" \;

    echo "Archived logs to $RUN_FOLDER"
}

trap cleanup SIGINT SIGTERM ERR
wait "$TRIN_BENCH_PID"
trap - SIGINT SIGTERM ERR
cleanup

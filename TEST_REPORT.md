# MQTT Security Experiments - Test Report

## Executive Summary

✅ **All experiments completed successfully!**  
All baseline, Phase 1, and Phase 2 tests are now running properly with verified results collection.

---

## Test Results

### Baseline Experiments

- **Status**: ✅ PASSED
- **Test**: Baseline TLS Certificate Handshake
- **Results**: 50 iterations of certificate-based TLS handshakes
- **Output**: `results_._baseline.csv`
- **Key Metrics**:
  - Handshake time: ~1.6-2.4ms per connection
  - CPU usage: 0.0-0.1%
  - Memory: ~8GB

### Phase 1A: Sequential Handshakes

- **Status**: ✅ PASSED
- **Test**: Sequential TLS Connections (200 total)
- **Results**: 50 iterations of sequential TLS handshakes
- **Output**: `results_phase1_phase1A_sequential.csv`
- **Key Metrics**:
  - Handshake time: ~1.4-2.7ms per connection
  - CPU usage: 0.1%
  - Memory: ~8GB

### Phase 1B: Concurrent Connections

- **Status**: ✅ PASSED
- **Test**: Concurrent Connection Scaling (10, 50, 100, 200, 400 clients)
- **Results**: Average latency and CPU usage for each concurrency level
- **Output**: `results_phase1_phase1B_concurrent.csv`
- **Key Metrics**:
  - 10 clients: 2.4ms avg, 0.3% CPU
  - 50 clients: 8.6ms avg, 0.3% CPU
  - 100 clients: 8.4ms avg, 0.3% CPU
  - 200 clients: 9.6ms avg, 0.4% CPU
  - 400 clients: 23.0ms avg, 0.5% CPU

### Phase 1C: Sustained Load

- **Status**: ✅ PASSED
- **Test**: Sustained Connection Load (300 seconds)
- **Results**: Connection latency and broker stats over time
- **Output**: `results_phase1_phase1C_sustained.csv`
- **Key Metrics**:
  - Handshake time: 3-4ms (stable)
  - CPU usage: 0.4%
  - Memory: ~30GB

### Phase 1D: Connection Lifetime

- **Status**: ✅ PASSED
- **Test**: Long-lived Connections (1, 10, 60 seconds)
- **Results**: Resource usage during different connection durations
- **Output**: `results_phase1_phase1D_lifetime.csv`
- **Key Metrics**:
  - Consistent CPU and memory usage across durations
  - CPU: 0.4%
  - Memory: ~30GB

### Phase 1E: Saturation Test

- **Status**: ✅ PASSED
- **Test**: Broker Saturation (50 to 1000 concurrent clients)
- **Results**: Success/failed connection counts at different client levels
- **Output**: `results_phase1_phase1E_saturation.csv`
- **Key Metrics**:
  - All clients from 50 to 1000 successfully connected
  - Success rate: 100%
  - Broker remained stable under extreme load

### Phase 2: TLS-PSK Authentication

- **Status**: ✅ PASSED
- **Test**: Pre-Shared Key TLS Handshakes
- **Results**: 50 iterations of PSK-based TLS handshakes
- **Output**: `results_._phase2_psk.csv`
- **Key Metrics**:
  - Handshake time: ~1.6-2.8ms per connection
  - CPU usage: 1.2-1.4%
  - Memory: ~33GB

---

## Fixed Issues

### 1. **Import Path Issues**

- **Problem**: Modules failed to import due to incorrect relative paths
- **Solution**: Standardized all Python imports to add experiments directory to sys.path
- **Files Fixed**:
  - `phase1B_concurrent/launcher.py`
  - `phase1C_sustained/sustained_load.py`
  - `phase1D_lifetime/client.py`
  - `phase1E_saturation/launcher.py`
  - `phase2_psk/client_connect.py`

### 2. **Certificate Path Resolution**

- **Problem**: Certificate paths were resolved relative to wrong directory levels
- **Solution**: Updated Path computations to correctly traverse to project root:
  - From `phase1/phaseXX/` files: go up 4 levels to project root
  - From `experiments/phase2_psk/` files: go up 3 levels to project root

### 3. **Script Working Directory Issues**

- **Problem**: Scripts using relative paths failed when run from different directories
- **Solution**:
  - Modified all shell scripts to detect their own directory using `$(dirname "${BASH_SOURCE[0]}")`
  - Updated all file references to use absolute paths
  - Fixed `baseline/run_baseline.sh` and `phase2_psk/run.sh`

### 4. **Shell Script Syntax Errors**

- **Problem**: Phase 1B had missing newline between commands
- **Solution**: Fixed `phase1B_concurrent/run.sh` syntax

---

## Unified Test Runner

Created `/home/excius/projects/mqtt-security/run_all_experiments.sh`:

- Executes all 7 test suites in sequence
- Validates broker status before starting
- Creates timestamped results directory
- Copies all result files to archive
- Provides comprehensive summary report
- Exit code: 0 (success) or 1 (failure)

### Usage:

```bash
cd /home/excius/projects/mqtt-security
bash run_all_experiments.sh
```

### Output:

- Timestamped results directory with all CSV files
- Summary of passed/failed tests
- Suitable for automated CI/CD pipelines

---

## Best Practices Implemented

### 1. **Consistent Path Handling**

- All scripts detect their own location using `$(dirname "${BASH_SOURCE[0]}")`
- Python files use pathlib for cross-platform path handling
- Absolute paths computed early and stored

### 2. **Error Handling**

- Broker status checked before running experiments
- Virtual environment activation verified
- Test results validated after execution

### 3. **Code Organization**

- Unified test runner instead of separate execute paths
- Consistent CSV output format across all tests
- Proper cleanup of stale results

### 4. **Measurement Consistency**

- All tests use the same `TLSHandshakeMeasurer` class
- Consistent timing measurements (milliseconds)
- CPU/Memory sampling standardized

---

## Results Directory Structure

```
results_20260306_230512/
├── results_._baseline.csv              (Baseline TLS certs)
├── results_phase1_phase1A_sequential.csv (Sequential handshakes)
├── results_phase1_phase1B_concurrent.csv  (Concurrent scaling)
├── results_phase1_phase1C_sustained.csv   (Sustained load)
├── results_phase1_phase1D_lifetime.csv    (Connection lifetime)
├── results_phase1_phase1E_saturation.csv  (Saturation test)
└── results_._phase2_psk.csv            (TLS-PSK handshakes)
```

---

## Recommendations for Future Work

1. **Automated Regression Testing**: Add the unified runner to CI/CD pipeline
2. **Performance Baselining**: Store baseline metrics to detect regressions
3. **Extended Duration Tests**: Phase 1C could run for longer periods (24+ hours)
4. **Load Generation Tools**: Consider using Apache Bench or specialized MQTT load tools
5. **Result Analysis**: Create Python scripts to analyze and compare results across runs

---

## Test Environment

- **Broker**: Mosquitto with TLS 1.2
- **TLS Configuration**: Certificate-based and PSK-based authentication
- **System**: Linux
- **Python Version**: 3.13
- **Test Date**: 2026-03-06
- **Broker Process ID**: 98781

---

## Troubleshooting Guide

### If broker isn't running:

```bash
mosquitto -c broker/mosquitto_tls.conf -d
```

### If virtual environment isn't activated:

```bash
source venv/bin/activate
```

### If results files aren't found:

- Check results are written to correct directory: `experiments/*/results.csv`
- Verify broker is responding to connections
- Check certificate files exist in `certs/` directory

### To run individual tests:

```bash
# Baseline
bash experiments/baseline/run_baseline.sh

# Phase 1A
bash experiments/phase1/phase1A_sequential/run.sh

# Phase 1B
bash experiments/phase1/phase1B_concurrent/run.sh

# Phase 1C
bash experiments/phase1/phase1C_sustained/run.sh

# Phase 1D
bash experiments/phase1/phase1D_lifetime/run.sh

# Phase 1E
timeout 120 bash experiments/phase1/phase1E_saturation/run.sh

# Phase 2
bash experiments/phase2_psk/run.sh
```

---

**Report Generated**: 2026-03-06  
**Status**: ✅ ALL TESTS PASSED

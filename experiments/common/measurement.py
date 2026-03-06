"""
Unified TLS handshake measurement and CPU monitoring for all experiments.
Uses clean ssl-level measurements without MQTT protocol overhead.
"""
import ssl
import socket
import time
import subprocess
from pathlib import Path


class TLSHandshakeMeasurer:
    """Measure TLS handshake time with minimal overhead."""
    
    def __init__(self, broker_host="localhost", broker_port=8883):
        self.broker_host = broker_host
        self.broker_port = broker_port
    
    def measure_cert_handshake(self, cafile, certfile, keyfile):
        """Measure certificate-based TLS handshake."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        s = socket.create_connection((self.broker_host, self.broker_port), timeout=5)
        ss = ctx.wrap_socket(s, server_hostname=self.broker_host, 
                            do_handshake_on_connect=False)
        
        try:
            t0 = time.perf_counter()
            ss.do_handshake()
            t1 = time.perf_counter()
            elapsed_ms = (t1 - t0) * 1000
        finally:
            try:
                ss.shutdown()
            except:
                pass
            try:
                ss.close()
            except:
                pass
        
        return elapsed_ms
    
    def measure_psk_handshake(self, psk_identity, psk_key_hex):
        """Measure PSK-based TLS handshake."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        def psk_callback(hint):
            return psk_identity.encode(), bytes.fromhex(psk_key_hex)
        
        ctx.set_psk_client_callback(psk_callback)
        
        s = socket.create_connection((self.broker_host, self.broker_port), timeout=5)
        ss = ctx.wrap_socket(s, server_hostname=self.broker_host,
                            do_handshake_on_connect=False)
        
        try:
            t0 = time.perf_counter()
            ss.do_handshake()
            t1 = time.perf_counter()
            elapsed_ms = (t1 - t0) * 1000
        finally:
            try:
                ss.shutdown()
            except:
                pass
            try:
                ss.close()
            except:
                pass
        
        return elapsed_ms


class CPUMonitor:
    """Monitor broker CPU and memory usage."""
    
    @staticmethod
    def get_broker_stats():
        """Get current broker CPU % and memory (KB)."""
        try:
            pid_output = subprocess.check_output(
                ["pidof", "mosquitto"], 
                stderr=subprocess.DEVNULL
            ).decode().strip()
            
            if not pid_output:
                return 0.0, 0
            
            pid = pid_output.split()[0]  # in case multiple instances
            
            cpu_output = subprocess.check_output(
                ["ps", "-p", pid, "-o", "%cpu="],
                stderr=subprocess.DEVNULL
            ).decode().strip()
            
            mem_output = subprocess.check_output(
                ["ps", "-p", pid, "-o", "rss="],
                stderr=subprocess.DEVNULL
            ).decode().strip()
            
            return float(cpu_output), int(mem_output)
        except Exception:
            return 0.0, 0
    
    @staticmethod
    def get_cpu_before_and_after(handshake_func, samples_before=2, samples_after=2):
        """
        Measure CPU usage before and after a handshake.
        Returns: (cpu_before, cpu_after, memory_kb)
        """
        # Sample CPU before handshake
        cpu_before_list = []
        for _ in range(samples_before):
            cpu, _ = CPUMonitor.get_broker_stats()
            cpu_before_list.append(cpu)
            time.sleep(0.05)
        
        # Run handshake
        handshake_func()
        
        # Sample CPU after handshake
        cpu_after_list = []
        for _ in range(samples_after):
            cpu, mem = CPUMonitor.get_broker_stats()
            cpu_after_list.append(cpu)
            time.sleep(0.05)
        
        cpu_before = sum(cpu_before_list) / len(cpu_before_list) if cpu_before_list else 0
        cpu_after = sum(cpu_after_list) / len(cpu_after_list) if cpu_after_list else 0
        
        return cpu_before, cpu_after, mem


# Vasi

> guardian, trustee.

## Dependencies

assuming ubuntu

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic gcc-multilib
```

## Block Mechanism

Detect attack -> block
If it keeps going, keep blocking (reset the expiration)
No more attack? Wait for 30s first for expiry -> block rule expired (except manual)

## Manual Blocklist

goes to `blacklist.txt` in the same folder, basically

## Testing

### SYN/TCP

> sudo hping3 -S -p 80 -i u1000 <INSERT_IP_HERE>

### ICMP

> sudo hping3 -1 -i u10000 <INSERT_IP_HERE>

### UDP

> sudo hping3 --udp -p 53 -i u500 <INSERT_IP_HERE>

### Port Scan

Don't forget to install `nmap` first before testing!

> sudo nmap -sS -p 1-65535 -T5 <INSERT_IP_HERE>

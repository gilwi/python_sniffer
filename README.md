# pythonLab
Repository dedicated to python course with M. DECKER

## Getting started

### Requirements

 - Coffee or beer
 - A linux host
 - iproute2 or ifconfig usage to get interface name you want to sniff
 
### Docker

Run with a single command:
```bash
docker compose up --build
```

### Vagrant

To start the VM and run the sniffer in one command:
```bash
vagrant up && vagrant ssh -c 'sudo python3 /app/sniffer/sniffer.py --interface all'
```

Alternatively, join the VM:
```bash
vagrant ssh
run-sniffer
```

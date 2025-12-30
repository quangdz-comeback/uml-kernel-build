# UML Kernel + SLIRP + Ubuntu Cloud Image

This guide shows how to boot an **User-Mode Linux (UML)** kernel with a Linux cloudimg using **SLIRP** for network connectivity.

---

## 1. Prerequisites

Make sure you have in the same directory:

- `linux` → UML kernel binary
- `slirp` → static SLIRP binary
- `disk.img` → Any Linux cloudimg

---

## 2. Boot UML

Run the following command from the directory containing the files:

```bash
./linux \
    mode=skas0 \
    mem=2048M \
    ubd0=disk.img \
    root=/dev/ubda1 \
    rw \
    init=/lib/systemd/systemd \
    eth0=slirp,,./slirp \
    con0=fd:0,fd:1 \
    con=null
````

### Explanation of key options:

* `mode=skas0` → required for SKAS0 mode for UML
* `mem=2048M` → allocate 2GB memory to the guest
* `ubd0=...` → the root filesystem image
* `root=/dev/ubda1 rw` → use first partition (partition 1) of UML disk as root, read-write mode
* `init=/lib/systemd/systemd` → start systemd as init
* `eth0=slirp,,./slirp` → connect guest `eth0` to SLIRP for network
* `con0=fd:0,fd:1` → console attached to current terminal
* `con=null` → disable other consoles

---

## 3. Setup Networking inside UML

Once inside the UML guest, configure the network to access the internet:

```bash
# Configure eth0 IP and bring it up
ip a add dev eth0 10.0.2.1
ip l set eth0 up

# Set default route
ip r add default dev eth0

# Configure DNS
echo "nameserver 10.0.2.3" > /etc/resolv.conf
```

After this, the guest should be able to access the internet via SLIRP.

For port forwarding, create a file named `slirp_config` in same folder and add forwarded port in format `[guest_port]:[host_port]` like this:
```
22:2222
80:8080
...
```

---

## 4. Notes

* You can use any Linux Cloud Image compatible with UML.
* Adjust `mem` parameter according to your host's available RAM.
* SLIRP allows network access without needing root privileges.


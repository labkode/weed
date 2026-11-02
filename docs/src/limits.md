---
title: 'Limits per account'
---

weed has the kernel limit what each Unix account uses: memory, CPU, I/O and processes, through the cgroup of its workers. The configuration sets the limits of every account. A limits file sets them otherwise for some users and groups, and weed re-reads it when it reloads. The network, weed does not limit itself (see [Network](#network)).

    [unix_users]
    cgroup_limits = ["memory.max=8G", "pids.max=5000"]
    limits = "/etc/weed/limits.json"

## The limits file {#file}

`unix_users.limits` names a JSON file of rules, each for a user or for a Unix group:

    [
      {"group": "cms", "cgroup_limits": ["memory.max=32G", "cpu.weight=400"]},
      {"user": "cmsprod", "cgroup_limits": ["cpu.weight=1000"]},
      {"user": "alice", "cgroup_limits": ["io.max=8:16 rbps=100000000 wbps=50000000"]}
    ]

| Key | Meaning |
|----|----|
| `user` | the account the rule is for |
| `group` | or the group whose members it is for: the account's primary group or one of its others, by name |
| `cgroup_limits` | file=value settings of the account's cgroup, as `unix_users.cgroup_limits` |

Each cgroup limit of an account comes from the first rule for the user that sets its file, else from the first rule for one of its groups that does, else from the configuration. With the file above, every member of cms gets memory.max=32G, cpu.weight=400 and pids.max=5000; cmsprod, if a member, the same with cpu.weight=1000; alice gets the defaults, and reads 100 MB/s and writes 50 MB/s at most of the block device 8:16. A limit set to its value without limit (memory.max=max) lifts one that a group or the configuration sets.

weed reads the file at startup, and does not start if it cannot. A misspelt key, a group that does not exist or a cgroup file that is not one makes the file unreadable; the kernel checks the values as weed writes them. When weed reloads (see [Reloading](reloading.html)), it reads the file again and writes the cgroup limits of the accounts that have workers at once. A file that cannot be read then keeps the previous rules, and the reload is partial:

    level=WARN msg="cannot read limits file, keeping the previous rules" file=/etc/weed/limits.json rules=3 error="/etc/weed/limits.json: json: unknown field \"cgroup_limit\""

## Memory, CPU and I/O {#cgroups}

The workers of each account run in a cgroup of their own (see [Unix accounts](unix-accounts.html#cgroups)). When one starts, weed writes the account's cgroup limits; when weed reloads, it writes them again for the accounts that have workers. The kernel applies a limit to the account's workers together, retired ones included.

    # cat /sys/fs/cgroup/system.slice/weed.service/worker-cms001/memory.max
    34359738368

A limit that is no longer configured stays as it was until the account's workers have all exited, since what lifts it depends on the file (memory.max=max, cpu.weight=100, ...). weed says so when it reloads; set the limit to its value without limit to lift it at once:

    level=WARN msg="a cgroup limit that is no longer configured stays until the account's workers have all exited; to lift it now, set it to the value without limit, e.g. memory.max=max" account=cms001 cgroup=/sys/fs/cgroup/system.slice/weed.service/worker-cms001 limit="cpu.weight=400"

weed sets cgroups up at startup when the configuration or the limits file has cgroup limits, or `unix_users.cgroups` is set. If a reload brings the first cgroup limits, restart weed to apply them.

The Go runtime of a worker keeps its memory below 90% of the lower of memory.max and memory.high, so that it collects garbage harder before the kernel reclaims its memory or kills it. A worker reads the limits of its cgroup when it starts and when weed reloads (GOMEMLIMIT, in weed's environment, prevails):

    level=INFO msg="set the Go memory limit from the cgroup's" worker.user=cms001 worker.pid=215 cgroup_memory_limit=17179869184 go_memory_limit=15461882262

## Network {#network}

weed does not pace transfers: the kernel does, on the network interface, with tc. A queueing discipline at the root limits what the machine sends: in total with htb or tbf, each connection with fq's maxrate, e.g.

    # tc qdisc replace dev eth0 root fq maxrate 2gbit

What it receives, a policer limits (tc's ingress qdisc), or a shaper on an ifb device that the traffic is redirected to. See tc(8), tc-htb(8) and tc-fq(8).

The kernel cannot tell the accounts apart there: the clients' transfers flow through weed's own process, which terminates TLS and relays them to the workers. What each account reads and writes of a block device, io.max in its cgroup limits (above); NFS and other network file systems have no block device of their own, and io.max does not apply to them.

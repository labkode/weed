---
title: 'Limits per account'
---

weed limits what each Unix account uses: memory, CPU, I/O and processes through the cgroup of its workers, and the network through rates that weed keeps itself. The configuration sets the limits of every account. A limits file sets them otherwise for some users and groups, and weed re-reads it when it reloads.

    [unix_users]
    cgroup_limits = ["memory.max=8G", "pids.max=5000"]
    limits = "/etc/weed/limits.json"

    [network]
    egress_rate = "9Gbit/s"
    ingress_rate = "9Gbit/s"
    account_egress_rate = "2Gbit/s"

## The limits file {#file}

`unix_users.limits` names a JSON file of rules, each for a user or for a Unix group:

    [
      {"group": "cms", "cgroup_limits": ["memory.max=32G", "cpu.weight=400"], "weight": 300, "egress_rate": "max"},
      {"user": "cmsprod", "weight": 1000},
      {"user": "alice", "ingress_rate": "10MB/s"}
    ]

| Key | Meaning |
|----|----|
| `user` | the account the rule is for |
| `group` | or the group whose members it is for: the account's primary group or one of its others, by name |
| `cgroup_limits` | file=value settings of the account's cgroup, as `unix_users.cgroup_limits` |
| `egress_rate` | the most the account sends, as `network.account_egress_rate` |
| `ingress_rate` | the most the account receives, as `network.account_ingress_rate` |
| `weight` | the account's share of the total rates, from 1 to 10000 (default 100) |

Each setting of an account comes from the first rule for the user that has it, else from the first rule for one of its groups that has it, else from the configuration. Cgroup limits are taken file by file in the same way. With the file above, every member of cms gets memory.max=32G, cpu.weight=400, pids.max=5000 and no egress rate; cmsprod gets the same with a weight of 1000; alice gets the defaults with an ingress rate of 10MB/s. A rate of "max" lifts a limit that a group or the configuration sets.

weed reads the file at startup, and does not start if it cannot. A misspelt key, a group that does not exist or a value out of range makes the file unreadable. When weed reloads (see [Reloading](reloading.html)), it reads the file again and applies it at once: the rates to transfers in progress, the cgroup limits to the accounts that have workers. A file that cannot be read then keeps the previous rules, and the reload is partial:

    level=WARN msg="cannot read limits file, keeping the previous rules" file=/etc/weed/limits.json rules=3 error="/etc/weed/limits.json: json: unknown field \"egres_rate\""

## Memory, CPU and I/O {#cgroups}

The workers of each account run in a cgroup of their own (see [Unix accounts](unix-accounts.html#cgroups)). When one starts, weed writes the account's cgroup limits; when weed reloads, it writes them again for the accounts that have workers. The kernel applies a limit to the account's workers together, retired ones included.

    # cat /sys/fs/cgroup/system.slice/weed.service/worker-cms001/memory.max
    34359738368

A limit that is no longer configured stays as it was until the account's workers have all exited, since what lifts it depends on the file (memory.max=max, cpu.weight=100, ...). weed says so when it reloads; set the limit to its value without limit to lift it at once:

    level=WARN msg="a cgroup limit that is no longer configured stays until the account's workers have all exited; to lift it now, set it to the value without limit, e.g. memory.max=max" account=cms001 cgroup=/sys/fs/cgroup/system.slice/weed.service/worker-cms001 limit="cpu.weight=400"

weed sets cgroups up at startup when the configuration or the limits file has cgroup limits, or `unix_users.cgroups` is set. If a reload brings the first cgroup limits, restart weed to apply them.

The Go runtime of a worker keeps its memory below 90% of the lower of memory.max and memory.high, so that it collects garbage harder before the kernel reclaims its memory or kills it. A worker reads the limits of its cgroup when it starts and when weed reloads (GOMEMLIMIT, in weed's environment, prevails):

    level=INFO msg="set the Go memory limit from the cgroup's" worker.user=cms001 worker.pid=215 cgroup_memory_limit=17179869184 go_memory_limit=15461882262

## Network rates {#network}

Egress are the bytes weed sends: downloads, and the third-party copies it pushes. Ingress are those it receives: uploads, and the third-party copies it pulls. The bodies of requests and responses count, their headers do not. Rates are written as "100MB/s", "10Gbit/s" or "1GiB/s" (k, M, G and T are powers of 1000, Ki, Mi, Gi and Ti of 1024), and "max" or "" is no limit.

`network.account_egress_rate` and `account_ingress_rate` are the most each account sends and receives, all its transfers together, unless the limits file says otherwise. `network.egress_rate` and `ingress_rate` are the most weed sends and receives, all accounts together.

weed relays what clients send and receive, and holds a transfer back when it is ahead of a rate. The workers make third-party copies themselves, and ask weed for each part they move, so the same rates apply to them. A rate is kept on average: a transfer moves a little before it waits (256 KiB, 512 KiB for a third-party copy), so a small file can go faster than its rate.

### Sharing the total by weight {#weights}

When a total rate holds transfers back, the accounts that want more than they get share it in proportion to their weights. An account that wants less than its share gets what it wants, and leaves the rest to the others; an account alone gets it all, up to its own rate. The weight is the account's, whatever the number of its transfers.

With the file above, an `egress_rate` of 40MB/s and an `account_egress_rate` of 30MB/s, cms001 (weight 300) and alice (weight 100) each downloaded 64 MiB at the same time. cms001 got 30MB/s, alice 10MB/s; once cms001 was done, alice got 30MB/s, her own rate:

    cms001 67108864 bytes in 2.291244 s: 29289269 B/s
    alice 67108864 bytes in 3.755363 s: 17870140 B/s

Weights decide who gets what only where weed is the bottleneck. When the network is, its queues decide, and they share among connections, not accounts. To decide it in weed, set the total rates a little below what the network carries, e.g. 9Gbit/s on a 10 Gbit/s link.

### What weed shows {#shows}

At startup:

    level=INFO msg="network rates are limited" egress_rate=40MB/s ingress_rate=40MB/s account_egress_rate=30MB/s account_ingress_rate=max limits_file=/etc/weed/limits.json

/status (see [Monitoring](monitoring.html#status)) has the total rates, in bytes per second (0: no limit), the rules of the limits file, and the rates and weight of each account with workers or requests in progress. held_egress and held_ingress are its transfers that a rate holds back now:

    # curl -s localhost:9100/status | jq .network
    {
      "egress_rate": 40000000,
      "ingress_rate": 40000000,
      "rules": 3,
      "accounts": [
        {
          "account": "alice",
          "egress_rate": 30000000,
          "ingress_rate": 10000000,
          "weight": 100,
          "held_egress": 1,
          "held_ingress": 0
        },
        {
          "account": "cms001",
          "egress_rate": 0,
          "ingress_rate": 0,
          "weight": 300,
          "held_egress": 1,
          "held_ingress": 0
        }
      ]
    }

`weed_network_delay_seconds_total{direction, limit}` adds up how long transfers waited, because of their account's rate (limit="account") or of the total (limit="total"). Its rate is how many transfers wait, on average:

    weed_network_delay_seconds_total{direction="egress",limit="account"} 3.47101971
    weed_network_delay_seconds_total{direction="egress",limit="total"} 4.321274925
    weed_network_delay_seconds_total{direction="ingress",limit="account"} 1.608468295

Without network rates and without a limits file, weed does not pace anything, and /status has no network section.

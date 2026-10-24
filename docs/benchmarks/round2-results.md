# Additional gains versus the first optimized version

| Workload | Before ms/op | After ms/op | Speedup | Before peak MiB | After peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| `object` | 32.647 | 22.619 | 1.44× | 22.41 | 17.92 |
| `object-long-keys` | 86.610 | 35.450 | 2.44× | 75.05 | 40.05 |
| `plist-entities` | 127.705 | 0.516 | 247.49× | 11.50 | 11.50 |
| `plist-text` | 89.927 | 21.203 | 4.24× | 129.36 | 33.42 |
| `plist-dates` | 32.693 | 6.681 | 4.89× | 11.62 | 11.62 |

[Method, verification and limits](../performance-round2.md).

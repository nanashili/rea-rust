# Measured medians

| Workload | Before ms/op | After ms/op | Speedup | Before peak MiB | After peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| `array` | 123.25 | 88.32 | 1.40× | 97.37 | 11.38 |
| `object` | 36.93 | 31.43 | 1.18× | 34.91 | 22.41 |
| `string` | 34.53 | 14.43 | 2.39× | 41.27 | 21.22 |
| `fuses` | 64.17 | 4.86 | 13.20× | 65.11 | 65.34 |
| `plist` | 32.42 | 5.58 | 5.81× | 97.41 | 33.36 |
| `delivery-fit` | 20.45 | 9.08 | 2.25× | 12.79 | 11.38 |
| `delivery-reject` | 265.40 | 53.12 | 5.00× | 134.69 | 31.54 |

See [methodology and limits](../performance.md). Raw samples: [formats.csv](formats.csv), [delivery.csv](delivery.csv).

# Results

## 16 CPUs (Buffers 64 MB)

2024-08-07T13:56:47+00:00
Running ./benchmark/bench
Run on (16 X 3604.35 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1024 KiB (x8)
  L3 Unified 36608 KiB (x1)
Load Average: 1.46, 2.22, 2.19

### Modern ebpf (Optimized before revert)

| metric | time      | cpu       | iterations |
| ------ | --------- | --------- | ---------- |
| mean   | 660327 us | 659736 us | 200        |
| median | 660258 us | 659671 us | 200        |
| stddev | 5651 us   | 5651 us   | 200        |
| cv     | 0.86 %    | 0.86 %    | 200        |

### Modern ebpf (Optimized after revert)

| metric | time      | cpu       | iterations |
| ------ | --------- | --------- | ---------- |
| mean   | 783413 us | 782798 us | 200        |
| median | 782926 us | 782289 us | 200        |
| stddev | 6068 us   | 6064 us   | 200        |
| cv     | 0.77 %    | 0.77 %    | 200        |

### Modern ebpf (Optimized after my fix)

| metric | time      | cpu       | iterations |
| ------ | --------- | --------- | ---------- |
| mean   | 660245 us | 659689 us | 200        |
| median | 660167 us | 659620 us | 200        |
| stddev | 4782 us   | 4782 us   | 200        |
| cv     | 0.81 %    | 0.81 %    | 200        |

### Modern ebpf (Default)

| metric | time       | cpu        | iterations |
| ------ | ---------- | ---------- | ---------- |
| mean   | 1199317 us | 1198685 us | 200        |
| median | 1198137 us | 1197514 us | 200        |
| stddev | 22111 us   | 22110 us   | 200        |
| cv     | 1.84 %     | 1.84 %     | 200        |

### ebpf (Optimized)

| metric | time      | cpu       | iterations |
| ------ | --------- | --------- | ---------- |
| mean   | 944180 us | 944001 us | 200        |
| median | 943148 us | 943048 us | 200        |
| stddev | 5727 us   | 5666 us   | 200        |
| cv     | 0.61 %    | 0.60 %    | 200        |

### ebpf (Default)

| metric | time       | cpu        | iterations |
| ------ | ---------- | ---------- | ---------- |
| mean   | 1386067 us | 1385860 us | 200        |
| median | 1385091 us | 1384974 us | 200        |
| stddev | 9264 us    | 9241 us    | 200        |
| cv     | 0.67 %     | 0.67 %     | 200        |

### Kmod (Optimized)

| metric | time      | cpu       | iterations |
| ------ | --------- | --------- | ---------- |
| mean   | 608670 us | 608592 us | 200        |
| median | 608174 us | 608097 us | 200        |
| stddev | 2956 us   | 2956 us   | 200        |
| cv     | 0.49 %    | 0.49 %    | 200        |

### Kmod (Default)

| metric | time       | cpu        | iterations |
| ------ | ---------- | ---------- | ---------- |
| mean   | 1228919 us | 1228815 us | 200        |
| median | 1228025 us | 1227949 us | 200        |
| stddev | 4195 us    | 4195 us    | 200        |
| cv     | 0.34 %     | 0.34 %     | 200        |

## 128 CPUs (Buffers 8 MB)

2024-08-07T15:38:39+00:00
Running ./benchmark/bench
Run on (128 X 2650 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x64)
  L1 Instruction 32 KiB (x64)
  L2 Unified 512 KiB (x64)
  L3 Unified 32768 KiB (x8)
Load Average: 0.91, 3.41, 3.84

### Modern ebpf (Optimized before revert)

| metric | time      | cpu       | iterations |
| ------ | --------- | --------- | ---------- |
| mean   | 373422 us | 372779 us | 50         |
| median | 372393 us | 371766 us | 50         |
| stddev | 5065 us   | 5064 us   | 50         |
| cv     | 1.36 %    | 1.36 %    | 50         |

### Modern ebpf (Optimized after revert)

| metric | time       | cpu        | iterations |
| ------ | ---------- | ---------- | ---------- |
| mean   | 4925453 us | 4924341 us | 50         |
| median | 4817052 us | 4815652 us | 50         |
| stddev | 300462 us  | 300452 us  | 50         |
| cv     | 6.10 %     | 6.10 %     | 50         |

### Modern ebpf (Optimized after my fix)

| metric | time      | cpu       | iterations |
| ------ | --------- | --------- | ---------- |
| mean   | 398426 us | 397771 us | 50         |
| median | 397460 us | 396799 us | 50         |
| stddev | 12555 us  | 12557 us  | 50         |
| cv     | 3.15 %    | 3.16 %    | 50         |

### Modern ebpf (Default)

| metric | time       | cpu        | iterations |
| ------ | ---------- | ---------- | ---------- |
| mean   | 6011485 us | 6010139 us | 50         |
| median | 6015853 us | 6014492 us | 50         |
| stddev | 106501 us  | 106480 us  | 50         |
| cv     | 1.77 %     | 1.77 %     | 50         |

### ebpf (Optimized)

| metric | time       | cpu        | iterations |
| ------ | ---------- | ---------- | ---------- |
| mean   | 3465255 us | 3464557 us | 50         |
| median | 3481945 us | 3479836 us | 50         |
| stddev | 59907 us   | 60021 us   | 50         |
| cv     | 1.73 %     | 1.73 %     | 50         |

### ebpf (Default)

| metric | time       | cpu        | iterations |
| ------ | ---------- | ---------- | ---------- |
| mean   | 4339419 us | 4338396 us | 50         |
| median | 4331416 us | 4330842 us | 50         |
| stddev | 47123 us   | 46817 us   | 50         |
| cv     | 1.09 %     | 1.08 %     | 50         |

### Kmod (Optimized)

| metric | time      | cpu       | iterations |
| ------ | --------- | --------- | ---------- |
| mean   | 390392 us | 390270 us | 50         |
| median | 391642 us | 391540 us | 50         |
| stddev | 4560 us   | 4548 us   | 50         |
| cv     | 1.17 %    | 1.17 %    | 50         |

### Kmod (Default)

| metric | time       | cpu        | iterations |
| ------ | ---------- | ---------- | ---------- |
| mean   | 8641843 us | 8640709 us | 50         |
| median | 8616543 us | 8615348 us | 50         |
| stddev | 296762 us  | 296736 us  | 50         |
| cv     | 3.43 %     | 3.43 %     | 50         |

# Rootkit
The Rootkit is a kernel mode Rootkit that hides all the processes that their name starts with $ROOT$

The Rootkit iterates all the processes by the LIST_ENTRY structure
The LIST_ENTRY structure has two members Flink (Forward Process) and Blink (Backward Process).
The following image can demonstrate that:
---
![Rootkit](DemonstrationImage1.png)

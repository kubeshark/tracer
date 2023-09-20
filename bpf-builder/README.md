
# Bpf builder

Currently we push the ebpf `*.o` files to source control, the motivation for it is to avoid the need for everyone to compile it in their PC.

This directory helps those who do want to build the .o files, it also serve as a documentation for the process of compiling the ebpf code.

## How to run ebpf-builder

From you shell, go to this directory and run `./build.sh`

Once the docker finished successfully, make sure to commit the four relevant files.
> tracer_bpfeb.go
> tracer_bpfel.go
> tracer_bpfeb.o
> tracer_bpfel.o

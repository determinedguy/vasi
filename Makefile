APP = xdp_ips
BPF_OBJ = $(APP).bpf.o
SKEL = $(APP).skel.h
USER_OBJ = $(APP).o

CC = clang
BPF_CC = clang

# Link against the system's libbpf
LIBS = -lbpf -lelf -lz

all: $(APP)

# 1. Compile BPF code to object file
$(BPF_OBJ): $(APP).bpf.c
	$(BPF_CC) -g -O2 -target bpf -c $< -o $@

# 2. Generate C skeleton header
$(SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# 3. Compile user-space object
$(USER_OBJ): $(APP).c $(SKEL)
	$(CC) -g -O2 -Wall -I. -c $< -o $@

# 4. Link user-space binary
$(APP): $(USER_OBJ)
	$(CC) -Wall -O2 -g $< $(LIBS) -o $@

clean:
	rm -f $(APP) $(BPF_OBJ) $(SKEL) $(USER_OBJ)
import os

def patch_file(path, old, new):
    if not os.path.exists(path):
        print(f"File tidak ditemukan: {path}")
        return
    with open(path, 'r') as f: 
        c = f.read()
    if old in c and new not in c:
        with open(path, 'w') as f: 
            f.write(c.replace(old, new))
        print(f"Berhasil mem-patch: {path}")
    else:
        print(f"Lewati (sudah dipatch atau pola tidak cocok): {path}")

# 1. include/uapi/linux/bpf.h
patch_file('include/uapi/linux/bpf.h', 
    'BPF_PROG_TYPE_SK_REUSEPORT,', 
    'BPF_PROG_TYPE_SK_REUSEPORT,\n\tBPF_PROG_TYPE_FLOW_DISSECTOR,\n\tBPF_PROG_TYPE_CGROUP_SYSCTL,\n\tBPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,\n\tBPF_PROG_TYPE_CGROUP_SOCKOPT,')
patch_file('include/uapi/linux/bpf.h', 
    'BPF_LIRC_MODE2,', 
    'BPF_LIRC_MODE2,\n\tBPF_FLOW_DISSECTOR,\n\tBPF_CGROUP_SYSCTL,\n\tBPF_CGROUP_GETSOCKOPT,\n\tBPF_CGROUP_SETSOCKOPT,')

# 2. include/linux/bpf_types.h
patch_file('include/linux/bpf_types.h', 
    'BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, cg_sock_addr)', 
    'BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, cg_sock_addr)\nBPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCKOPT, cg_sockopt)')

# 3. net/core/filter.c
cg_ops = '''const struct bpf_verifier_ops cg_sockopt_verifier_ops = {
	.get_func_proto		= sock_filter_func_proto,
	.is_valid_access	= sock_filter_is_valid_access,
};
const struct bpf_prog_ops cg_sockopt_prog_ops = {
};'''
patch_file('net/core/filter.c', 
    'const struct bpf_prog_ops cg_sock_addr_prog_ops = {\n};', 
    'const struct bpf_prog_ops cg_sock_addr_prog_ops = {\n};\n' + cg_ops)

# 4. kernel/bpf/syscall.c
patch_file('kernel/bpf/syscall.c', 
    'case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:', 
    'case BPF_PROG_TYPE_CGROUP_SOCKOPT:\n\t\tswitch (expected_attach_type) {\n\t\tcase BPF_CGROUP_GETSOCKOPT:\n\t\tcase BPF_CGROUP_SETSOCKOPT:\n\t\t\treturn 0;\n\t\tdefault:\n\t\t\treturn -EINVAL;\n\t\t}\n\tcase BPF_PROG_TYPE_CGROUP_SOCK_ADDR:')
patch_file('kernel/bpf/syscall.c', 
    'case BPF_CGROUP_INET4_CONNECT:', 
    'case BPF_CGROUP_GETSOCKOPT:\n\tcase BPF_CGROUP_SETSOCKOPT:\n\t\tptype = BPF_PROG_TYPE_CGROUP_SOCKOPT;\n\t\tbreak;\n\tcase BPF_CGROUP_INET4_CONNECT:')
patch_file('kernel/bpf/syscall.c', 
    'case BPF_CGROUP_INET4_CONNECT:', 
    'case BPF_CGROUP_GETSOCKOPT:\n\tcase BPF_CGROUP_SETSOCKOPT:\n\t\tptype = BPF_PROG_TYPE_CGROUP_SOCKOPT;\n\t\tbreak;\n\tcase BPF_CGROUP_INET4_CONNECT:')

print('Selesai menerapkan injeksi BPF!')

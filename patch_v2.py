import os

def rewrite():
    # 1. bpf.h
    with open('include/uapi/linux/bpf.h', 'r') as f: c = f.read()
    if 'BPF_PROG_TYPE_CGROUP_SOCKOPT = 25' not in c:
        c = c.replace('BPF_PROG_TYPE_SK_REUSEPORT,', 'BPF_PROG_TYPE_SK_REUSEPORT,\n\tBPF_PROG_TYPE_FLOW_DISSECTOR = 22,\n\tBPF_PROG_TYPE_CGROUP_SYSCTL = 23,\n\tBPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,\n\tBPF_PROG_TYPE_CGROUP_SOCKOPT = 25,')
    if 'BPF_CGROUP_GETSOCKOPT = 21' not in c:
        c = c.replace('BPF_CGROUP_UDP6_RECVMSG,', 'BPF_CGROUP_UDP6_RECVMSG,\n\tBPF_CGROUP_GETSOCKOPT = 21,\n\tBPF_CGROUP_SETSOCKOPT = 22,')
    with open('include/uapi/linux/bpf.h', 'w') as f: f.write(c)

    # 2. bpf_types.h
    with open('include/linux/bpf_types.h', 'r') as f: c = f.read()
    if 'BPF_PROG_TYPE_CGROUP_SOCKOPT' not in c:
        c = c.replace('BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, cg_sock_addr)', 'BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, cg_sock_addr)\nBPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCKOPT, cg_sockopt)')
    with open('include/linux/bpf_types.h', 'w') as f: f.write(c)

    # 3. filter.c
    with open('net/core/filter.c', 'r') as f: c = f.read()
    cg_ops = '''const struct bpf_verifier_ops cg_sockopt_verifier_ops = {
	.get_func_proto		= sock_filter_func_proto,
	.is_valid_access	= sock_filter_is_valid_access,
};
const struct bpf_prog_ops cg_sockopt_prog_ops = {
};'''
    if 'cg_sockopt_verifier_ops' not in c:
        c = c.replace('const struct bpf_prog_ops cg_sock_addr_prog_ops = {\n};', 'const struct bpf_prog_ops cg_sock_addr_prog_ops = {\n};\n' + cg_ops)
    with open('net/core/filter.c', 'w') as f: f.write(c)

    # 4. syscall.c
    with open('kernel/bpf/syscall.c', 'r') as f: c = f.read()
    
    c = c.replace(
        'case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:\n\t\treturn attach_type == prog->expected_attach_type ? 0 : -EINVAL;',
        'case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:\n\t\treturn attach_type == prog->expected_attach_type ? 0 : -EINVAL;\n\tcase BPF_PROG_TYPE_CGROUP_SOCKOPT:\n\t\treturn attach_type == prog->expected_attach_type ? 0 : -EINVAL;'
    )
    
    c = c.replace('case BPF_CGROUP_UDP6_RECVMSG:\n\t\t\treturn 0;', 'case BPF_CGROUP_UDP6_RECVMSG:\n\t\tcase BPF_CGROUP_GETSOCKOPT:\n\t\tcase BPF_CGROUP_SETSOCKOPT:\n\t\t\treturn 0;')
    c = c.replace('case BPF_CGROUP_UDP6_RECVMSG:\n\t\tptype = BPF_PROG_TYPE_CGROUP_SOCK_ADDR;', 'case BPF_CGROUP_UDP6_RECVMSG:\n\t\tptype = BPF_PROG_TYPE_CGROUP_SOCK_ADDR;\n\t\tbreak;\n\tcase BPF_CGROUP_GETSOCKOPT:\n\tcase BPF_CGROUP_SETSOCKOPT:\n\t\tptype = BPF_PROG_TYPE_CGROUP_SOCKOPT;')
    c = c.replace('case BPF_CGROUP_UDP6_RECVMSG:\n\tcase BPF_CGROUP_SOCK_OPS:', 'case BPF_CGROUP_UDP6_RECVMSG:\n\tcase BPF_CGROUP_GETSOCKOPT:\n\tcase BPF_CGROUP_SETSOCKOPT:\n\tcase BPF_CGROUP_SOCK_OPS:')
    
    with open('kernel/bpf/syscall.c', 'w') as f: f.write(c)
    print("Injeksi V2 Berhasil!")

rewrite()

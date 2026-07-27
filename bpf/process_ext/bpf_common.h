/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __PROCESS_EXT_BPF_COMMON_H
#define __PROCESS_EXT_BPF_COMMON_H

/*
 * Common BPF helpers for process extension modules: PID filtering and
 * aggregated map updates. Included by process.bpf.c before feature modules.
 * References maps and flags defined in the glue file.
 */

static __always_inline bool is_pid_tracked(void)
{
	if (!filter_pids)
		return true;  /* no filter mode: trace all */
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	return bpf_map_lookup_elem(&tracked_pids, &pid) != NULL;
}

static __always_inline bool is_cgroup_tracked(void)
{
	if (filter_pid_namespace) {
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		u32 pid_namespace = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
		if (pid_namespace != target_pid_namespace)
			return false;
	}
	if (filter_cgroup) {
		u64 cgroup_id = bpf_get_current_cgroup_id();
		if (cgroup_id == target_cgroup_id)
			return true;
		if (!filter_cgroup_children)
			return false;
		return bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id) != NULL;
	}
	return true;
}

static __always_inline bool is_event_tracked(void)
{
	return is_cgroup_tracked() && is_pid_tracked();
}

static __always_inline void update_agg_map(struct agg_key *key, u64 count, u64 bytes)
{
	struct agg_value *val = bpf_map_lookup_elem(&event_agg_map, key);
	if (val) {
		__sync_fetch_and_add(&val->count, count);
		if (bytes)
			__sync_fetch_and_add(&val->total_bytes, bytes);
		val->last_ts = bpf_ktime_get_ns();
		bpf_get_current_comm(val->comm, sizeof(val->comm));
	} else {
		struct agg_value new_val = {};
		new_val.count = count;
		new_val.total_bytes = bytes;
		new_val.first_ts = bpf_ktime_get_ns();
		new_val.last_ts = new_val.first_ts;
		bpf_get_current_comm(new_val.comm, sizeof(new_val.comm));

		if (bpf_map_update_elem(&event_agg_map, key, &new_val, BPF_NOEXIST) < 0) {
			/* map full: bump overflow counter */
			u32 zero = 0;
			u64 *overflow = bpf_map_lookup_elem(&agg_overflow_count, &zero);
			if (overflow)
				__sync_fetch_and_add(overflow, 1);
		}
	}
}

/* Format "fd=N" into a detail buffer. */
static __always_inline void format_fd_detail(char *buf, int buf_len, int fd)
{
	BPF_SNPRINTF(buf, buf_len, "fd=%d", fd);
}

/* Format "N.N.N.N:PORT" for IPv4 addresses. */
static __always_inline void format_ipv4_port(char *buf, int buf_len, u32 ip, u16 port)
{
	u8 o0 = ip & 0xFF;
	u8 o1 = (ip >> 8) & 0xFF;
	u8 o2 = (ip >> 16) & 0xFF;
	u8 o3 = (ip >> 24) & 0xFF;
	BPF_SNPRINTF(buf, buf_len, "%u.%u.%u.%u:%u", o0, o1, o2, o3, port);
}

#endif /* __PROCESS_EXT_BPF_COMMON_H */

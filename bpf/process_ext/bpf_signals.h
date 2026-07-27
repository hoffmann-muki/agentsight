/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef __PROCESS_EXT_BPF_SIGNALS_H
#define __PROCESS_EXT_BPF_SIGNALS_H

/* Process coordination tracepoints: setpgid, setsid, kill, fork. */

SEC("tp/syscalls/sys_enter_setpgid")
int trace_setpgid(struct trace_event_raw_sys_enter *ctx)
{
	if (!trace_signals)
		return 0;
	if (!is_event_tracked())
		return 0;

	int target_pid = (int)ctx->args[0];
	int pgid = (int)ctx->args[1];

	struct agg_key key = {};
	key.pid = bpf_get_current_pid_tgid() >> 32;
	key.event_type = EVENT_TYPE_PGRP_CHANGE;

	BPF_SNPRINTF(key.detail, sizeof(key.detail), "pid=%d,pgid=%d", target_pid, pgid);

	update_agg_map(&key, 1, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_setsid")
int trace_setsid(struct trace_event_raw_sys_enter *ctx)
{
	if (!trace_signals)
		return 0;
	if (!is_event_tracked())
		return 0;

	u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct agg_key key = {};
	key.pid = pid;
	key.event_type = EVENT_TYPE_SESSION_CREATE;

	BPF_SNPRINTF(key.detail, sizeof(key.detail), "sid=%u", pid);

	update_agg_map(&key, 1, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_kill")
int trace_kill(struct trace_event_raw_sys_enter *ctx)
{
	if (!trace_signals)
		return 0;
	if (!is_event_tracked())
		return 0;

	int target_pid = (int)ctx->args[0];
	int sig = (int)ctx->args[1];

	struct agg_key key = {};
	key.pid = bpf_get_current_pid_tgid() >> 32;
	key.event_type = EVENT_TYPE_SIGNAL_SEND;

	BPF_SNPRINTF(key.detail, sizeof(key.detail), "target=%d,sig=%d", target_pid, sig);

	update_agg_map(&key, 1, 0);
	return 0;
}

SEC("tp/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	if (!trace_signals)
		return 0;
	if (!is_event_tracked())
		return 0;

	struct agg_key key = {};
	key.pid = bpf_get_current_pid_tgid() >> 32;
	key.event_type = EVENT_TYPE_PROC_FORK;
	/* detail left empty: aggregate fork count per parent pid */

	update_agg_map(&key, 1, 0);
	return 0;
}

#endif /* __PROCESS_EXT_BPF_SIGNALS_H */

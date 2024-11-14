//! Process management syscalls
#[allow(unused)]
use core::ptr;

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE},
    mm::{
        check_map_area_mapping, check_map_area_unmapping, frame_available,
        translated_and_write_bytes, MapArea, MapPermission, MapType, VirtAddr,
    },
    task::{
        change_program_brk, current_user_token, exit_current_and_run_next,
        get_current_task_task_info_inner, mapping_address_for_current_task,
        suspend_current_and_run_next, unmapping_address_for_current_task, TaskStatus,
    },
    timer::{get_time_ms, get_time_us},
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");

    let us = get_time_us();
    let tv_inner = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };

    let tv_inner_ptr = &tv_inner as *const TimeVal as *const u8;
    let tv_inner_len = core::mem::size_of::<TimeVal>();

    translated_and_write_bytes(
        current_user_token(),
        ts as usize as *const u8,
        tv_inner_ptr,
        tv_inner_len,
    );

    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info");

    let current_task_info = get_current_task_task_info_inner();
    let task_info = TaskInfo {
        status: TaskStatus::Running,
        syscall_times: current_task_info.syscall_times,
        time: get_time_ms() - current_task_info.first_run_time,
    };

    let ptr = &task_info as *const TaskInfo as *const u8;
    let len = core::mem::size_of::<TaskInfo>();

    translated_and_write_bytes(current_user_token(), ti as usize as *const u8, ptr, len);

    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if port & 0x7 == 0 || port & !0x7 != 0 || start & (PAGE_SIZE - 1) != 0 {
        return -1;
    }

    let end = start + len;
    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(end);
    let mut map_perssion = MapPermission::U;

    if port & 0x01 == 0x01 {
        map_perssion |= MapPermission::R;
    }

    if port & 0x02 == 0x02 {
        map_perssion |= MapPermission::W;
    }

    if port & 0x04 == 0x04 {
        map_perssion |= MapPermission::X;
    }

    let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perssion);

    if !frame_available(map_area.vpn_len()) {
        return -1;
    }

    // 构造页表检查是否已经存在映射
    if check_map_area_mapping(current_user_token(), map_area) {
        return -1;
    }

    // 建立映射
    mapping_address_for_current_task(start_va, end_va, map_perssion);

    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");

    if start % PAGE_SIZE != 0 {
        return -1;
    }

    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(start + len);

    let map_area = MapArea::new(start_va, end_va, MapType::Framed, MapPermission::U);

    if check_map_area_unmapping(current_user_token(), map_area) {
        return -1;
    }

    unmapping_address_for_current_task(start_va, end_va);

    0
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

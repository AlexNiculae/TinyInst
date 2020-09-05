//
//  MachTarget.h
//  TinyInst
//
//  Created by Alexandru-Vlad Niculae on 14/07/2020.
//  Copyright © 2020 Google LLC. All rights reserved.
//

#ifndef MachTarget_h
#define MachTarget_h

#include <mach/mach.h>

class MachTarget {
private:
  pid_t pid;
  task_t task;
  mach_port_t exception_port;
  vm_size_t m_page_size;
  int pointer_size;

  exception_mask_t       saved_masks[EXC_TYPES_COUNT];
  mach_port_t            saved_ports[EXC_TYPES_COUNT];
  exception_behavior_t   saved_behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t  saved_flavors[EXC_TYPES_COUNT];
  mach_msg_type_number_t saved_exception_types_count;

  size_t MaxBytesLeftInPage(mach_vm_address_t address, mach_vm_size_t size);

public:
  MachTarget(pid_t target_pid);

  pid_t Pid() { return pid; }
  task_t Task() { return task; }
  mach_port_t ExceptionPort() { return exception_port; }

  vm_size_t PageSize();

  kern_return_t BasicInfo(mach_task_basic_info *info);
  void GetRegionSubmapInfo(mach_vm_address_t *region_address,
                           mach_vm_size_t *region_size,
                           vm_region_submap_info_data_64_t *info);

  bool ExceptionPortIsValid();
  bool TaskIsValid();

  kern_return_t WaitForException(uint32_t timeout, mach_msg_header_t *req, uint32_t size);
  void ReplyToException(mach_msg_header_t *rpl);

  void FreeMemory(uint64_t address, size_t size);
  void ReadMemory(uint64_t address, size_t size, void *buf);
  void WriteMemory(uint64_t address, const void *buf, size_t size);
  void ProtectMemory(uint64_t address, uint64_t size, vm_prot_t protection);

  void Exit();
};

#endif /* MachTarget_h */

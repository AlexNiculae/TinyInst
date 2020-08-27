//
//  MachTarget.cpp
//  DebuggerMacOs
//
//  Created by Alexandru-Vlad Niculae on 17/07/2020.
//  Copyright © 2020 Google LLC. All rights reserved.
//

#include <stdio.h>
#include <cstdlib>

#include <mach/mach_vm.h>
#include <mach-o/dyld_images.h>

#include "MachTarget.h"
#include "../common.h"

MachTarget::MachTarget(pid_t target_pid): pid(target_pid) {
  kern_return_t krt;

  krt = task_for_pid(mach_task_self(), pid, &task);
  if (krt != KERN_SUCCESS) {
    FATAL("task_for_pid failed with error %d\n", krt);
  }

  krt = task_get_exception_ports(task,
                                  EXC_MASK_ALL,
                                  saved_masks,
                                  &saved_exception_types_count,
                                  saved_ports,
                                  saved_behaviors,
                                  saved_flavors);
  if (krt != KERN_SUCCESS) {
    FATAL("Unable to save the exception ports registered in the process, %d\n", krt);
  }

  krt = mach_port_allocate(mach_task_self(),
                           MACH_PORT_RIGHT_RECEIVE,
                           &exception_port);
  if (krt != KERN_SUCCESS) {
    FATAL("Unable to allocate a new port, %x\n", krt);
  }

  mach_port_insert_right(mach_task_self(),
                         exception_port,
                         exception_port,
                         MACH_MSG_TYPE_MAKE_SEND);
  if (krt != KERN_SUCCESS) {
    FATAL("Unable to authorize the new port, %d\n", krt);
  }

  /* register the exception port with the target process */
  task_set_exception_ports(task,
                           EXC_MASK_ALL,
                           exception_port,
                           EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                           x86_THREAD_STATE64);
  if (krt != KERN_SUCCESS) {
    FATAL("Unable to register the exception port with the target process, %x\n", krt);
  }
}


kern_return_t MachTarget::BasicInfo(mach_task_basic_info *info) {
  if (info == NULL) {
    return KERN_INVALID_ARGUMENT;
  }

  unsigned int count = MACH_TASK_BASIC_INFO_COUNT;
  return task_info(task, MACH_TASK_BASIC_INFO, (task_info_t)info, &count);
}

bool MachTarget::ExceptionPortIsValid() {
  return MACH_PORT_VALID(exception_port);
}


bool MachTarget::TaskIsValid() {
  if (task != TASK_NULL) {
    mach_task_basic_info task_info;
    return BasicInfo(&task_info) == KERN_SUCCESS;
  }

  return false;
}

void MachTarget::GetRegionSubmapInfo(mach_vm_address_t *region_address,
                                     mach_vm_size_t *region_size,
                                     vm_region_submap_info_data_64_t *info) {
  kern_return_t krt;
  uint32_t depth = ~0;
  mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
  krt = mach_vm_region_recurse(task,
                               region_address,
                               region_size,
                               &depth,
                               (vm_region_recurse_info_t)info,
                               &count);

  if (krt != KERN_SUCCESS) {
    FATAL("Unable to retrieve region information, %d\n", krt);
  }
}

kern_return_t MachTarget::WaitForException(uint32_t timeout, mach_msg_header_t *req, uint32_t size) {
  kern_return_t krt;
  krt = mach_msg(req,  /* receive buffer */
                 MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT,
                 0,                         /* size of send buffer */
                 size,                      /* size of receive buffer */
                 exception_port,            /* port to receive on */
                 timeout,                   /* wait for timeout seconds */
                 MACH_PORT_NULL);           /* notify port, unused */

  return krt;
}

void MachTarget::ReplyToException(mach_msg_header_t *rpl) {
  kern_return_t krt;
  krt = mach_msg(rpl,  /* send buffer */
                MACH_SEND_MSG | MACH_SEND_INTERRUPT,             /* send message */
                rpl->msgh_size,            /* size of send buffer */
                0,                         /* size of receive buffer */
                MACH_PORT_NULL,            /* port to receive on */
                MACH_MSG_TIMEOUT_NONE,     /* wait indefinitely */
                MACH_PORT_NULL);           /* notify port, unused */

  if (krt != MACH_MSG_SUCCESS) {
    FATAL("Unable to send reply to exception port, %d\n", krt);
  }
}

void MachTarget::Exit() {
  /* restore saved exception ports */
  for (int i = 0; i < saved_exception_types_count; ++i) {
      task_set_exception_ports(task,
                               saved_masks[i],
                               saved_ports[i],
                               saved_behaviors[i],
                               saved_flavors[i]);
  }

  mach_port_deallocate(mach_task_self(), exception_port);
}

void MachTarget::FreeMemory(uint64_t address, size_t size) {
  kern_return_t krt;
  krt = mach_vm_deallocate(task, (mach_vm_address_t)address, (mach_vm_size_t)size);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%d) freeing memory @ 0x%llx\n", krt, address);
  }
}

size_t MachTarget::ReadMemory(uint64_t address, size_t size, void *buf) {
  mach_vm_size_t dataCnt = 0;
  kern_return_t krt;

  krt = mach_vm_read_overwrite(task,
                              (mach_vm_address_t)address,
                              (mach_vm_size_t)size,
                              (mach_vm_address_t)buf,
                              &dataCnt);

  if (krt != KERN_SUCCESS) {
    FATAL("Error (%d) reading memory @ address 0x%llx\n", krt, address);
  }

  return dataCnt;
}

void MachTarget::WriteMemory(uint64_t address, void *buf, size_t size) {
  kern_return_t krt;

  ProtectMemory(address, size, VM_PROT_ALL | VM_PROT_COPY);
  krt = mach_vm_write(task,
                      (mach_vm_address_t)address,
                      (vm_offset_t)buf,
                      (mach_msg_type_number_t)size);

  if (krt != KERN_SUCCESS) {
    FATAL("Error (%d) writing memory @ 0x%llx\n", krt, address);
  }
}

void MachTarget::ProtectMemory(uint64_t address, uint64_t size, vm_prot_t protection) {
  kern_return_t krt;

  krt = mach_vm_protect(task, address, size, false, protection);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%d) applying memory protection @ 0x%llx\n", krt, address);
  }
}

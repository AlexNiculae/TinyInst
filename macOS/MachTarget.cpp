//
//  MachTarget.cpp
//  TinyInst
//
//  Created by Alexandru-Vlad Niculae on 17/07/2020.
//  Copyright © 2020 Google LLC. All rights reserved.
//

#include <stdio.h>
#include <cstdlib>
#include <string.h>

#include <mach/mach_vm.h>
#include <mach-o/dyld_images.h>

#include "MachTarget.h"
#include "../common.h"

static const vm_size_t kInvalidPageSize = ~0;

MachTarget::MachTarget(pid_t target_pid): pid(target_pid), m_page_size(kInvalidPageSize) {
  kern_return_t krt;

  krt = task_for_pid(mach_task_self(), pid, &task);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) calling task_for_pid\n", mach_error_string(krt));
  }

  krt = task_get_exception_ports(task,
                                  EXC_MASK_ALL,
                                  saved_masks,
                                  &saved_exception_types_count,
                                  saved_ports,
                                  saved_behaviors,
                                  saved_flavors);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) saving the exception ports registered in the process\n", mach_error_string(krt));
  }

  krt = mach_port_allocate(mach_task_self(),
                           MACH_PORT_RIGHT_RECEIVE,
                           &exception_port);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) allocating a new port\n", mach_error_string(krt));
  }

  mach_port_insert_right(mach_task_self(),
                         exception_port,
                         exception_port,
                         MACH_MSG_TYPE_MAKE_SEND);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) authorizing a new exception port\n", mach_error_string(krt));
  }

  /* register the exception port with the target process */
  task_set_exception_ports(task,
                           EXC_MASK_ALL,
                           exception_port,
                           EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                           x86_THREAD_STATE64);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) registering the exception port with the target process\n", mach_error_string(krt));
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
    FATAL("Error (%s) retrieving region information\n", mach_error_string(krt));
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
    FATAL("Error (%s) sending reply to exception port\n", mach_error_string(krt));
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

  kern_return_t krt;
  krt = mach_port_destroy(mach_task_self(), exception_port);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) destroying exception port\n", mach_error_string(krt));
  }

  krt = mach_port_deallocate(mach_task_self(), task);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) deallocating task port", mach_error_string(krt));
  }

}

void MachTarget::FreeMemory(uint64_t address, size_t size) {
  if (size == 0) {
    WARN("FreeMemory is called with size == 0\n");
    return;
  }

  kern_return_t krt = mach_vm_deallocate(task, (mach_vm_address_t)address, (mach_vm_size_t)size);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) freeing memory @ 0x%llx\n", mach_error_string(krt), address);
  }
}

void MachTarget::ReadMemory(uint64_t address, size_t size, void *buf) {
  if (buf == NULL) {
    WARN("ReadMemory is called with buf == NULL\n");
    return;
  }

  if (size == 0) {
    WARN("ReadMemory is called with size == 0\n");
    return;
  }

  kern_return_t krt;
  mach_vm_size_t total_bytes_read = 0;
  mach_vm_address_t cur_addr = address;
  uint8_t *cur_buf = (uint8_t*)buf;
  while (total_bytes_read < size) {
    mach_vm_size_t cur_size = MaxBytesLeftInPage(cur_addr, size - total_bytes_read);

    mach_msg_type_number_t cur_bytes_read = 0;
    vm_offset_t vm_buf;
    krt = mach_vm_read(task, cur_addr, cur_size, &vm_buf, &cur_bytes_read);

    if (krt != KERN_SUCCESS) {
      FATAL("Error (%s) reading memory @ address 0x%llx\n", mach_error_string(krt), cur_addr);
    }

    if (cur_bytes_read != cur_size) {
      FATAL("Error reading the entire requested memory @ address 0x%llx\n", cur_addr);
    }

    memcpy(cur_buf, (const void*)vm_buf, cur_bytes_read);
    mach_vm_deallocate(mach_task_self(), vm_buf, cur_bytes_read);

    total_bytes_read += cur_bytes_read;
    cur_addr += cur_bytes_read;
    cur_buf += cur_bytes_read;
  }
}

void MachTarget::WriteMemory(uint64_t address, const void *buf, size_t size) {
  if (buf == NULL) {
    WARN("WriteMemory is called with buf == NULL\n");
    return;
  }

  if (size == 0) {
    WARN("WriteMemory is called with size == 0\n");
    return;
  }

  ProtectMemory(address, size, VM_PROT_ALL | VM_PROT_COPY);
  kern_return_t krt = mach_vm_write(task,
                                    (mach_vm_address_t)address,
                                    (vm_offset_t)buf,
                                    (mach_msg_type_number_t)size);

  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) writing memory @ 0x%llx\n", mach_error_string(krt), address);
  }
}

void MachTarget::ProtectMemory(uint64_t address, uint64_t size, vm_prot_t protection) {
  if (size == 0) {
    WARN("ProtectMemory is called with size == 0\n");
    return;
  }

  kern_return_t krt = mach_vm_protect(task, address, size, false, protection);
  if (krt != KERN_SUCCESS) {
    FATAL("Error (%s) applying memory protection @ 0x%llx\n", mach_error_string(krt), address);
  }
}


size_t MachTarget::MaxBytesLeftInPage(mach_vm_address_t address, mach_vm_size_t size) {
  vm_size_t page_size = PageSize();
  if (page_size > 0) {
    mach_vm_size_t page_offset = address % page_size;
    mach_vm_size_t bytes_left_in_page = page_size - page_offset;
    if (size > bytes_left_in_page) {
      size = bytes_left_in_page;
    }
  }

  return size;
}

vm_size_t MachTarget::PageSize() {
  if (m_page_size == kInvalidPageSize) {
    kern_return_t krt;

    task_vm_info_data_t vm_info;
    mach_msg_type_number_t info_count = TASK_VM_INFO_COUNT;
    krt = task_info(task, TASK_VM_INFO, (task_info_t)&vm_info, &info_count);

    if (krt != KERN_SUCCESS) {
      FATAL("Error (%s) retrieving target's TASK_VM_INFO\n", mach_error_string(krt));
    }

    m_page_size = vm_info.page_size;
  }

  return m_page_size;
}

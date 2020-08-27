//
//  DebuggerMacOs.cpp
//  DebuggerMacOs
//
//  Created by Alexandru-Vlad Niculae on 06/07/2020.
//  Copyright © 2020 Google LLC. All rights reserved.
//

#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <algorithm>

#include <mach/mach.h>
#include <mach/mach_vm.h>

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>

#include <dlfcn.h>

#include <spawn.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>

#include "Debugger.h"
#include "../common.h"

#define BREAKPOINT_UNKNOWN 0
#define BREAKPOINT_ENTRYPOINT 1
#define BREAKPOINT_TARGET 2
#define BREAKPOINT_NOTIFICATION 3

#define PERSIST_END_EXCEPTION 0x0F22
#define TRAP_FLAG 0x0100
#define TWO_GB_OF_MEMORY 0x80000000

std::unordered_map<task_t, class Debugger*> Debugger::task_to_debugger_map;

vm_prot_t Debugger::MacOSProtectionFlags(MemoryProtection memory_protection) {
  switch (memory_protection) {
    case READONLY:
      return VM_PROT_READ;

    case READWRITE:
      return VM_PROT_READ | VM_PROT_WRITE;

    case READEXECUTE:
      return VM_PROT_READ | VM_PROT_EXECUTE;

    case READWRITEEXECUTE:
      return VM_PROT_ALL;

    default:
      FATAL("Unimplemented memory protection");
  }
}

void Debugger::RemoteFree(void *address, size_t size) {
  mach_target->FreeMemory((uint64_t)address, size);
}

void Debugger::RemoteRead(void *address, void *buffer, size_t size) {
  mach_target->ReadMemory((uint64_t)address, size, buffer);
}

void Debugger::RemoteWrite(void *address, void *buffer, size_t size) {
  mach_target->WriteMemory((uint64_t)address, buffer, size);
}

void Debugger::RemoteProtect(void *address, size_t size, MemoryProtection protect) {
  RemoteProtect(address, size, MacOSProtectionFlags(protect));
}

void Debugger::RemoteProtect(void *address, size_t size, vm_prot_t protect) {
  mach_target->ProtectMemory((uint64_t)address, size, protect);
}


void Debugger::CreateException(MachException *mach_exception, Exception *exception) {
  exception->ip = (void*)GetRegister(RIP);

  switch (mach_exception->exception_type) {
    case EXC_BREAKPOINT:
      exception->type = BREAKPOINT;
      exception->ip = (void*)((uint64_t)exception->ip - 1);
      break;

    case EXC_BAD_ACCESS:
      exception->type = ACCESS_VIOLATION;
      break;

    case EXC_BAD_INSTRUCTION:
      exception->type = ILLEGAL_INSTRUCTION;
      break;

    default:
      exception->type = OTHER;
      break;
  }

  exception->maybe_execute_violation = false;
  exception->maybe_write_violation = false;
  exception->access_address = 0;

  if (mach_exception->exception_type == EXC_BAD_ACCESS) {
    if (mach_exception->code[0] == KERN_PROTECTION_FAILURE) {
      exception->maybe_write_violation = true;
      exception->maybe_execute_violation = true;
    }

    exception->access_address = (void*)mach_exception->code[1];
  }
}

uint64_t* Debugger::GetPointerToRegister(Register r) {
  x86_thread_state64_t *state = (x86_thread_state64_t*)(mach_exception->new_state);
  switch (r) {
    case RAX:
      return &state->__rax;
    case RCX:
      return &state->__rcx;
    case RDX:
      return &state->__rdx;
    case RBX:
      return &state->__rbx;
    case RSP:
      return &state->__rsp;
    case RBP:
      return &state->__rbp;
    case RSI:
      return &state->__rsi;
    case RDI:
      return &state->__rdi;
    case R8:
      return &state->__r8;
    case R9:
      return &state->__r9;
    case R10:
      return &state->__r10;
    case R11:
      return &state->__r11;
    case R12:
      return &state->__r12;
    case R13:
      return &state->__r13;
    case R14:
      return &state->__r14;
    case R15:
      return &state->__r15;
    case RIP:
      return &state->__rip;
    case RFLAGS:
      return &state->__rflags;

    default:
      FATAL("Unimplemented register");
  }
}

size_t Debugger::GetRegister(Register r) {
  uint64_t *reg_pointer = GetPointerToRegister(r);
  return *reg_pointer;
}

void Debugger::SetRegister(Register r, size_t value) {
  uint64_t *reg_pointer = GetPointerToRegister(r);
  *reg_pointer = value;
}

Debugger::Register Debugger::ArgumentToRegister(int arg) {
  switch (arg) {
    case 0:
      return RDI;

    case 1:
      return RSI;

    case 2:
      return RDX;

    case 3:
      return RCX;

    case 4:
      return R8;

    case 5:
      return R9;

    default:
      FATAL("Argument %d not valid\n", arg);
      break;
  }
}

void Debugger::GetMachHeader(void *mach_header_address, mach_header_64 *mach_header) {
  RemoteRead(mach_header_address, (void*)mach_header, sizeof(mach_header_64));
}

void Debugger::GetLoadCommandsBuffer(void *mach_header_address, const mach_header_64 *mach_header, void **load_commands) {
  *load_commands = (void*)malloc(mach_header->sizeofcmds);
  RemoteRead((void*)((uint64_t)mach_header_address + sizeof(mach_header_64)), *load_commands, mach_header->sizeofcmds);
}

template <class TCMD>
void Debugger::GetLoadCommand(mach_header_64 mach_header,
                              void *load_commands_buffer,
                              uint32_t load_cmd_type,
                              const char segname[16],
                              TCMD **ret_command) {
  uint64_t load_cmd_addr = (uint64_t)load_commands_buffer;
  for (int i = 0; i < mach_header.ncmds; ++i) {
    load_command *load_cmd = (load_command *)load_cmd_addr;
    if (load_cmd->cmd == load_cmd_type) {
      TCMD *t_cmd = (TCMD*)load_cmd;
      if (load_cmd_type != LC_SEGMENT_64
          || !strcmp(((segment_command_64*)t_cmd)->segname, segname)) {
        *ret_command = (TCMD*)load_cmd;
        return;
      }
    }

    load_cmd_addr += load_cmd->cmdsize;
  }
}


void *Debugger::RemoteAllocateNear(uint64_t region_min,
                                        uint64_t region_max,
                                        size_t size,
                                        MemoryProtection protection) {
  uint64_t min_address, max_address;

  //try after first
  min_address = region_max;
  max_address = (UINT64_MAX - region_min < TWO_GB_OF_MEMORY) ? UINT64_MAX : region_min + TWO_GB_OF_MEMORY;
  void *ret_address = RemoteAllocateAfter(min_address, max_address, size, protection);
  if (ret_address != NULL) {
    return ret_address;
  }

  //try before second
  min_address = (region_max < TWO_GB_OF_MEMORY) ? 0 : region_max - TWO_GB_OF_MEMORY;
  max_address = (region_min < size) ? 0 : region_min - size;
  return RemoteAllocateBefore(min_address, max_address, size, protection);
}

void *Debugger::RemoteAllocateBefore(uint64_t min_address,
                                          uint64_t max_address,
                                          size_t size,
                                          MemoryProtection protection) {
  kern_return_t krt;
  bool retried = false;

  vm_prot_t protection_flags = MacOSProtectionFlags(protection);

  mach_vm_address_t cur_address = max_address;
  while (cur_address > min_address) {
    size_t step = size;

    mach_vm_address_t region_address = cur_address;
    mach_vm_size_t region_size = 0;
    vm_region_submap_info_data_64_t info;
    mach_target->GetRegionSubmapInfo(&region_address, &region_size, &info);

    if (region_address <= cur_address) { /* cur_address references allocated memory */
      cur_address = region_address;
    }
    else { /* cur_address references unallocated memory */
      uint64_t free_region_size = region_address - cur_address;
      if (free_region_size >= size) {
        void *ret_address = (void*)(cur_address + (free_region_size - size));
        krt = mach_vm_allocate(mach_target->Task(),
                               (mach_vm_address_t*)&ret_address,
                               size,
                               VM_FLAGS_FIXED);

        if (!(min_address <= (uint64_t)ret_address && (uint64_t)ret_address <= max_address)) {
          return NULL;
        }

        if (krt == KERN_NO_SPACE && !retried) {
          krt = mach_vm_deallocate(mach_target->Task(), (mach_vm_address_t)cur_address, free_region_size);
          if (krt == KERN_SUCCESS) {
            retried = true;
            continue;
          }
        }

        retried = false;
        if (krt == KERN_SUCCESS) {
          RemoteProtect(ret_address, size, protection_flags);
          return ret_address;
        }
      }
      else {
        step = size - free_region_size;
      }
    }

    if (cur_address < step) break;
    cur_address -= step;
  }

  return NULL;
}

void *Debugger::RemoteAllocateAfter(uint64_t min_address,
                                         uint64_t max_address,
                                         size_t size,
                                         MemoryProtection protection) {
  kern_return_t krt;
  bool retried = false;

  vm_prot_t protection_flags = MacOSProtectionFlags(protection);

  mach_vm_address_t cur_address = min_address;
  while (cur_address < max_address) {
    mach_vm_address_t region_address = cur_address;
    mach_vm_size_t region_size = 0;
    vm_region_submap_info_data_64_t info;
    mach_target->GetRegionSubmapInfo(&region_address, &region_size, &info);

    if (region_address <= cur_address) { /* cur_address references allocated memory */
      cur_address = region_address + region_size;
      continue;
    }

    /* cur_address references unallocated memory */
    if (region_address > max_address) {
      region_address = max_address;
    }

    uint64_t free_region_size = region_address - cur_address;
    if (free_region_size >= size) {
      void *ret_address = (void*)cur_address;
      krt = mach_vm_allocate(mach_target->Task(),
                             (mach_vm_address_t*)&ret_address,
                             size,
                             VM_FLAGS_FIXED);

      if (!(min_address <= (uint64_t)ret_address && (uint64_t)ret_address <= max_address)) {
        return NULL;
      }

      if (krt == KERN_NO_SPACE && !retried) {
        krt = mach_vm_deallocate(mach_target->Task(), (mach_vm_address_t)cur_address, free_region_size);
        if (krt == KERN_SUCCESS) {
          retried = true;
          continue;
        }
      }

      retried = false;
      if (krt == KERN_SUCCESS) {
        RemoteProtect(ret_address, size, protection_flags);
        return ret_address;
      }
    }

    cur_address = region_address;
  }

  return NULL;
}


void Debugger::DeleteBreakpoints() {
  for (auto iter = breakpoints.begin(); iter != breakpoints.end(); iter++) {
    delete *iter;
  }
  breakpoints.clear();
}


void Debugger::AddBreakpoint(void *address, int type) {
  Breakpoint *new_breakpoint = new Breakpoint;

  RemoteRead(address, &(new_breakpoint->original_opcode), 1);

  unsigned char cc = 0xCC;
  RemoteWrite(address, (void*)&cc, 1);

  new_breakpoint->address = address;
  new_breakpoint->type = type;
  breakpoints.push_back(new_breakpoint);
}


void Debugger::HandleTargetReachedInternal() {
  saved_sp = (void*)GetRegister(RSP);
  RemoteRead(saved_sp, &saved_return_address, child_ptr_size);

  if (loop_mode) {
    for (int arg_index = 0; arg_index < 6 && arg_index < target_num_args; ++arg_index) {
      saved_args[arg_index] = (void*)GetRegister(ArgumentToRegister(arg_index));
    }

    if (target_num_args > 6) {
      RemoteRead((void*)((uint64_t)saved_sp + child_ptr_size),
                 saved_args + 6,
                 child_ptr_size * (target_num_args - 6));
    }
  }

  size_t return_address = PERSIST_END_EXCEPTION;
  RemoteWrite(saved_sp, &return_address, child_ptr_size);

  if (!target_reached) {
    target_reached = true;
    OnTargetMethodReached();
  }
}


void Debugger::HandleTargetEnded() {
  if (loop_mode) {
    SetRegister(RIP, (size_t)target_address);
    SetRegister(RSP, (size_t)saved_sp);

    size_t return_address = PERSIST_END_EXCEPTION;
    RemoteWrite(saved_sp, &return_address, child_ptr_size);

    for (int arg_index = 0; arg_index < 6 && arg_index < target_num_args; ++arg_index) {
      SetRegister(ArgumentToRegister(arg_index), (size_t)saved_args[arg_index]);

      if (target_num_args > 6) {
        RemoteWrite((void*)((uint64_t)saved_sp + child_ptr_size),
                    saved_args + 6,
                    child_ptr_size * (target_num_args - 6));
      }
    }
  }
  else {
    SetRegister(RIP, (size_t)saved_return_address);
    AddBreakpoint((void*)GetTranslatedAddress((size_t)target_address), BREAKPOINT_TARGET);
  }
}

void Debugger::OnEntrypoint() {
  child_entrypoint_reached = true;
  if (trace_debug_events) {
    SAY("Debugger: Process entrypoint reached\n");
  }
}


void Debugger::ExtractCodeRanges(void *base_address,
                                 size_t min_address,
                                 size_t max_address,
                                 std::list<AddressRange> *executable_ranges,
                                 size_t *code_size) {
  mach_header_64 mach_header;
  GetMachHeader(base_address, &mach_header);

  void *load_commands_buffer = NULL;
  GetLoadCommandsBuffer(base_address, &mach_header, &load_commands_buffer);

  segment_command_64 *text_cmd = NULL;
  GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd);
  if (text_cmd == NULL) {
    FATAL("Unable to find __TEXT command in ExtractCodeRanges\n");
  }

  uint64_t file_vm_slide = (uint64_t)base_address - text_cmd->vmaddr;

  *code_size = 0;
  for (auto &it: *executable_ranges) {
    free(it.data);
  }
  executable_ranges->clear();
  AddressRange new_range;

  uint64_t load_cmd_addr = (uint64_t)load_commands_buffer;
  for (int i = 0; i < mach_header.ncmds; ++i) {
    load_command *load_cmd = (load_command *)load_cmd_addr;
    if (load_cmd->cmd == LC_SEGMENT_64) {
      segment_command_64 *segment_cmd = (segment_command_64*)load_cmd;

      if (!strcmp(segment_cmd->segname, "__PAGEZERO") || !strcmp(segment_cmd->segname, "__LINKEDIT")) {
        load_cmd_addr += load_cmd->cmdsize;
        continue;
      }

      mach_vm_address_t segment_start_addr = (mach_vm_address_t)segment_cmd->vmaddr + file_vm_slide;
      mach_vm_address_t segment_end_addr = (mach_vm_address_t)segment_cmd->vmaddr + segment_cmd->vmsize + file_vm_slide;

      mach_vm_address_t cur_address = segment_start_addr;

      while (true) {
        mach_vm_size_t region_size = 0;
        vm_region_submap_info_data_64_t info;
        mach_target->GetRegionSubmapInfo(&cur_address, &region_size, &info);

        if (segment_end_addr <= cur_address) {
          break;
        }

        new_range.from = cur_address;
        new_range.to = cur_address + region_size;

        if (new_range.from < segment_start_addr) {
          new_range.from = segment_start_addr;
        }

        if (segment_end_addr < new_range.to) {
          new_range.to = segment_end_addr;
        }

        if (info.protection & VM_PROT_EXECUTE) {
          size_t range_size = new_range.to - new_range.from;
          new_range.data = (char *)malloc(range_size);
          RemoteRead((void*)new_range.from, new_range.data, range_size);

          kern_return_t krt;
          krt = mach_vm_deallocate(mach_target->Task(), (mach_vm_address_t)new_range.from, range_size);

          if (krt == KERN_SUCCESS) {
            mach_vm_address_t alloc_address = new_range.from;
            krt = mach_vm_allocate(mach_target->Task(),
                                   (mach_vm_address_t*)&alloc_address,
                                   range_size,
                                   VM_FLAGS_FIXED);

            if (krt == KERN_SUCCESS && alloc_address && new_range.from) {
              RemoteWrite((void*)new_range.from, new_range.data, range_size);
            }
            else {
              FATAL("Unable to allocate memory after deallocate in ExtractCodeRanges\n");
            }
          }

          RemoteProtect((void*)new_range.from, range_size, info.protection ^ VM_PROT_EXECUTE);

          executable_ranges->push_back(new_range);
          *code_size += range_size;

          mach_vm_address_t region_addr = new_range.from;
          mach_vm_size_t region_sz = range_size;
          vm_region_submap_info_data_64_t region_info;
          mach_target->GetRegionSubmapInfo(&region_addr, (mach_vm_size_t*)&region_sz, &region_info);
          if (region_info.protection & VM_PROT_EXECUTE) {
            FATAL("Failed to mark the original code to NON-EXECUTABLE\n");
          }
        }

        cur_address += region_size;
      }
    }

    load_cmd_addr += load_cmd->cmdsize;
  }

  free(load_commands_buffer);
}


void Debugger::ProtectCodeRanges(std::list<AddressRange> *executable_ranges) {
  for (auto &range: *executable_ranges) {
    mach_vm_address_t region_address = range.from;
    mach_vm_size_t region_size = 0;
    vm_region_submap_info_data_64_t info;
    mach_target->GetRegionSubmapInfo(&region_address, &region_size, &info);

    if (region_address != range.from
        || region_address + region_size != range.to
        || !(info.protection & VM_PROT_EXECUTE)) {
      FATAL("Error in ProtectCodeRanges. Target incompatible with persist_instrumentation_data");
    }

    RemoteProtect((void*)region_address, region_size, info.protection ^ VM_PROT_EXECUTE);
  }
}

void Debugger::GetImageSize(void *base_address, size_t *min_address, size_t *max_address) {
  mach_header_64 mach_header;
  GetMachHeader(base_address, &mach_header);

  void *load_commands_buffer = NULL;
  GetLoadCommandsBuffer(base_address, &mach_header, &load_commands_buffer);

  *min_address = SIZE_MAX;
  *max_address = 0;

  uint64_t load_cmd_addr = (uint64_t)load_commands_buffer;
  for (int i = 0; i < mach_header.ncmds; ++i) {
    load_command *load_cmd = (load_command *)load_cmd_addr;
    if (load_cmd->cmd == LC_SEGMENT_64) {
      segment_command_64 *segment_cmd = (segment_command_64*)load_cmd;

      if (!strcmp(segment_cmd->segname, "__PAGEZERO") || !strcmp(segment_cmd->segname, "__LINKEDIT")) {
        load_cmd_addr += load_cmd->cmdsize;
        continue;
      }

      if (segment_cmd->vmaddr < *min_address) {
        *min_address = segment_cmd->vmaddr;
      }

      if (segment_cmd->vmaddr + segment_cmd->vmsize > *max_address) {
        *max_address = segment_cmd->vmaddr + segment_cmd->vmsize;
      }
    }

    load_cmd_addr += load_cmd->cmdsize;
  }

  segment_command_64 *text_cmd = NULL;
  GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd);
  if (text_cmd == NULL) {
    FATAL("Unable to find __TEXT command in ExtractCodeRanges\n");
  }

  uint64_t file_vm_slide = (uint64_t)base_address - text_cmd->vmaddr;
  *min_address += file_vm_slide;
  *max_address += file_vm_slide;

  free(load_commands_buffer);
}


void *Debugger::GetModuleEntrypoint(void *base_address) {
  mach_header_64 mach_header;
  GetMachHeader(base_address, &mach_header);
  if (mach_header.filetype != MH_EXECUTE) {
    return NULL;
  }

  void *load_commands_buffer = NULL;
  GetLoadCommandsBuffer(base_address, &mach_header, &load_commands_buffer);

  entry_point_command *entry_point_cmd = NULL;
  GetLoadCommand(mach_header, load_commands_buffer, LC_MAIN, NULL, &entry_point_cmd);
  if (entry_point_cmd == NULL) {
    FATAL("Unable to find ENTRY POINT command in GetModuleEntrypoint\n");
  }

  uint64_t entryoff = entry_point_cmd->entryoff;

  free(load_commands_buffer);
  return (void*)((uint64_t)base_address + entryoff);
}

bool Debugger::IsDyld(void *base_address) {
  mach_header_64 mach_header;
  GetMachHeader(base_address, &mach_header);

  return (mach_header.filetype == MH_DYLINKER);
}


void *Debugger::GetSymbolAddress(void *base_address, char *symbol_name) {
  mach_header_64 mach_header;
  GetMachHeader(base_address, &mach_header);

  void *load_commands_buffer = NULL;
  GetLoadCommandsBuffer(base_address, &mach_header, &load_commands_buffer);

  symtab_command *symtab_cmd = NULL;
  GetLoadCommand(mach_header, load_commands_buffer, LC_SYMTAB, NULL, &symtab_cmd);
  if (symtab_cmd == NULL) {
    FATAL("Unable to find SYMTAB command in GetSymbolAddress\n");
  }

  segment_command_64 *linkedit_cmd = NULL;
  GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__LINKEDIT", &linkedit_cmd);
  if (linkedit_cmd == NULL) {
    FATAL("Unable to find __LINKEDIT command in GetSymbolAddress\n");
  }

  segment_command_64 *text_cmd = NULL;
  GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT", &text_cmd);
  if (text_cmd == NULL) {
    FATAL("Unable to find __TEXT command in GetSymbolAddress\n");
  }

  uint64_t file_vm_slide = (uint64_t)base_address - text_cmd->vmaddr;

  char *strtab = (char*)malloc(symtab_cmd->strsize);
  uint64_t strtab_addr = linkedit_cmd->vmaddr + file_vm_slide + symtab_cmd->stroff - linkedit_cmd->fileoff;
  RemoteRead((void*)strtab_addr, strtab, symtab_cmd->strsize);

  void *symbol_address = NULL;
  nlist_64 symbol;

  for (int i = 0; i < symtab_cmd->nsyms && !symbol_address; ++i) {
    uint64_t nlist_addr = linkedit_cmd->vmaddr + file_vm_slide + symtab_cmd->symoff - linkedit_cmd->fileoff + i * sizeof(nlist_64);

    symbol = {0};
    RemoteRead((void*)nlist_addr, &symbol, sizeof(nlist_64));

    if ((symbol.n_type & N_TYPE) == N_SECT) {
      char *sym_name_start = strtab + symbol.n_un.n_strx;

      if (!strcmp(sym_name_start, symbol_name)) {
        symbol_address = (void*)((uint64_t)base_address - text_cmd->vmaddr + symbol.n_value);
        break;
      }
    }
  }

  free(strtab);
  free(load_commands_buffer);
  return symbol_address;
}

void *Debugger::GetTargetAddress(void *base_address) {
  if (!target_offset) {
    void *method_address = GetSymbolAddress(base_address, target_method);
    if (method_address == NULL) {
      FATAL("Unable to find address of target method\n");
    }

    target_offset = (uint64_t)method_address - (uint64_t)base_address;
  }

  return (void*)((uint64_t)base_address + target_offset);
}

void Debugger::OnModuleLoaded(void *module, char *module_name) {
  if (trace_debug_events) {
    SAY("Debugger: Loaded module %s at %p\n", module_name, module);
  }

  if (!attach_mode) {
    void *entrypoint = GetModuleEntrypoint(module);
    if (entrypoint) {
      AddBreakpoint(entrypoint, BREAKPOINT_ENTRYPOINT);
    }
  }

  if (IsDyld(module)) {
    m_dyld_debugger_notification = GetSymbolAddress(module, (char*)"__dyld_debugger_notification");
    AddBreakpoint(m_dyld_debugger_notification, BREAKPOINT_NOTIFICATION);

    // This is a hack that can save us the recurring TRAP FLAG breakpoint on BREAKPOINT_NOTIFICATION.
    unsigned char c3 = 0xC3;
    RemoteWrite((void*)((uint64_t)m_dyld_debugger_notification+1), (void*)&c3, 1);
  }

  if (target_function_defined && !strcasecmp(module_name, target_module)) {
    target_address = GetTargetAddress(module);
    if (!target_address) {
      FATAL("Error determing target method address\n");
    }

    AddBreakpoint(target_address, BREAKPOINT_TARGET);
  }
}


void Debugger::OnDyldImageNotifier(size_t mode, unsigned long infoCount, uint64_t machHeaders[]) {
  uint64_t *image_info_array = new uint64_t[infoCount];
  size_t image_info_array_size = sizeof(uint64_t) * infoCount;
  RemoteRead(machHeaders, (void*)image_info_array, image_info_array_size);

  if (mode == 1) { /* dyld_image_removing */
    for (unsigned long i = 0; i < infoCount; ++i) {
      OnModuleUnloaded((void*)image_info_array[i]);
    }
  }
  else {
    kern_return_t krt;
    dyld_process_info info =
        m_dyld_process_info_create(mach_target->Task(), 0, &krt);

    if (krt != KERN_SUCCESS) {
      FATAL("Unable to retrieve dyld_process_info_create information\n");
    }

    if (info) {
      m_dyld_process_info_for_each_image(
        info,
        ^(uint64_t mach_header_addr, const uuid_t uuid, const char *path) {
          if (mode == 2) { /* dyld_notify_remove_all */
            // TO DO - test this
            printf("******dyld_notify_remove_all received\n\n");
            OnModuleUnloaded((void*)mach_header_addr);
          }
          else if (std::find(image_info_array, image_info_array + infoCount, mach_header_addr) != image_info_array + infoCount) {
            /* dyld_image_adding */
            char *base_name = strrchr((char*)path, '/');
            base_name = (base_name) ? base_name + 1 : (char*)path;
            OnModuleLoaded((void*)mach_header_addr, base_name);
          }
        });

      m_dyld_process_info_release(info);
    }
  }

  delete [] image_info_array;
}

void Debugger::OnProcessCreated() {
  kern_return_t krt;
  dyld_process_info info =
      m_dyld_process_info_create(mach_target->Task(), 0, &krt);

  if (krt != KERN_SUCCESS) {
    FATAL("Unable to retrieve dyld_process_info_create information\n");
  }

  if (info) {
    m_dyld_process_info_for_each_image(
      info,
      ^(uint64_t mach_header_addr, const uuid_t uuid, const char *path) {
        if (attach_mode || IsDyld((void*)mach_header_addr)) {
          char *base_name = strrchr((char*)path, '/');
          base_name = (base_name) ? base_name + 1 : (char*)path;
          OnModuleLoaded((void*)mach_header_addr, (char*)path);
        }
      });

    m_dyld_process_info_release(info);
  }
}


int Debugger::HandleDebuggerBreakpoint() {
  int ret = BREAKPOINT_UNKNOWN;

  Breakpoint *breakpoint = NULL, *tmp_breakpoint;
  for (auto iter = breakpoints.begin(); iter != breakpoints.end(); iter++) {
    tmp_breakpoint = *iter;
    if (tmp_breakpoint->address == (void*)((uint64_t)last_exception.ip)) {
      breakpoint = tmp_breakpoint;
      if (breakpoint->type == BREAKPOINT_NOTIFICATION) {
        OnDyldImageNotifier(GetRegister(ArgumentToRegister(0)),
                            (unsigned long)GetRegister(ArgumentToRegister(1)),
                            (uint64_t*)GetRegister(ArgumentToRegister(2)));

        return BREAKPOINT_NOTIFICATION;
      }

      breakpoints.erase(iter);
      break;
    }
  }

  if (!breakpoint) {
    return ret;
  }

  RemoteWrite(breakpoint->address, &breakpoint->original_opcode, 1);
  SetRegister(RIP, GetRegister(RIP) - 1); //INTEL

  switch (breakpoint->type) {
    case BREAKPOINT_ENTRYPOINT:
      OnEntrypoint();
      break;

    case BREAKPOINT_TARGET:
      if (trace_debug_events) {
        SAY("Target method reached\n");
      }

      HandleTargetReachedInternal();
      break;

    default:
      break;
  }

  ret = breakpoint->type;
  free(breakpoint);

  return ret;
}


//TO DO - fix mach exception address
void Debugger::HandleExceptionInternal(MachException *raised_mach_exception) {
  mach_exception = raised_mach_exception;
  CreateException(mach_exception, &last_exception);

  dbg_continue_status = KERN_SUCCESS;
  ret_HandleExceptionInternal = DEBUGGER_CONTINUE;

  if (mach_exception->exception_type == EXC_BREAKPOINT) {
    int breakpoint_type = HandleDebuggerBreakpoint();
    if (breakpoint_type == BREAKPOINT_TARGET) {
      ret_HandleExceptionInternal = DEBUGGER_TARGET_START;
      return;
    }
    else if (breakpoint_type != BREAKPOINT_UNKNOWN) {
      return;
    }
  }

  if (OnException(&last_exception)) {
    return;
  }

  if (trace_debug_events) {
    SAY("Debugger: Mach exception %d at address %p\n", mach_exception->exception_type, last_exception.ip);
  }

  switch(mach_exception->exception_type) {
    case EXC_RESOURCE:
      ret_HandleExceptionInternal = DEBUGGER_HANGED;
      break;

    case EXC_BAD_ACCESS:
    bad_access_label:
      if (target_function_defined && last_exception.ip == (void*)PERSIST_END_EXCEPTION) {
        if (trace_debug_events) {
          SAY("Debugger: Persistence method ended\n");
        }

        HandleTargetEnded();
        ret_HandleExceptionInternal = DEBUGGER_TARGET_END;
      }
      else {
        dbg_continue_status = KERN_FAILURE;
        ret_HandleExceptionInternal = DEBUGGER_CRASHED;
      }
      break;

    case EXC_BAD_INSTRUCTION:
    case EXC_ARITHMETIC:
    case EXC_CRASH:
    case EXC_GUARD:
    crash_label:
      dbg_continue_status = KERN_FAILURE;
      ret_HandleExceptionInternal = DEBUGGER_CRASHED;
      break;

    case EXC_BREAKPOINT:
      dbg_continue_status = KERN_FAILURE;
      break;

    //Unix signals
    case EXC_SOFTWARE:
      if (mach_exception->codeCnt < 2 || mach_exception->code[0] != EXC_SOFT_SIGNAL) {
        goto default_label;
      }

      switch (mach_exception->code[1]) {
        case SIGSEGV:
        case SIGBUS:
          goto bad_access_label;

        case SIGILL:
        case SIGFPE:
        case SIGABRT:
        case SIGSYS:
        case SIGPIPE:
          goto crash_label;

        /* Handling the Unix soft signal produced by attaching via ptrace
          PT_ATTACHEXC suspends the process by using a SIGSTOP signal */
        case SIGSTOP:
          if (trace_debug_events) {
            SAY("Debugger: Process created or attached\n");
          }

          OnProcessCreated();

          mach_exception->code[1] = 0;
          ptrace(PT_THUPDATE,
                 mach_target->Pid(),
                (caddr_t)(uintptr_t)mach_exception->thread_port,
                (int)mach_exception->code[1]);

          break;

        default:
          goto default_label;

        case SIGCHLD:
          if (trace_debug_events) {
            SAY("Debugger: Process exit\n");
          }

          ret_HandleExceptionInternal = DEBUGGER_PROCESS_EXIT;
          OnProcessExit();
      }

      break;

    default:
    default_label:
      if (trace_debug_events) {
        WARN("Debugger: Unhandled exception, mach exception_type %x at address %p\n", mach_exception->exception_type, last_exception.ip);
      }
      dbg_continue_status = KERN_FAILURE;
  }
}


DebuggerStatus Debugger::DebugLoop(uint32_t timeout) {
  if (mach_target->ExceptionPortIsValid() && dbg_continue_needed) {
    task_resume(mach_target->Task());
    mach_target->ReplyToException(reply_buffer);
  }

  bool alive = true;
  while (alive) {
    dbg_continue_needed = false;

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    int wait_time = (timeout > 100) ? 100 : timeout;
    kern_return_t krt = mach_target->WaitForException(wait_time, request_buffer,
                                                      sizeof(union __RequestUnion__catch_mach_exc_subsystem));
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

    task_suspend(mach_target->Task());

    long long time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
    timeout = (1LL * timeout >= time_elapsed) ? timeout - (uint32_t)time_elapsed : 0;

    switch (krt) {
      case MACH_RCV_TIMED_OUT:
        if (timeout == 0) {
          return DEBUGGER_HANGED;
        }

        if (!mach_target->TaskIsValid() || !mach_target->ExceptionPortIsValid()) {
          goto exit_label;
        }

        continue;

      case MACH_RCV_INTERRUPTED:
        if (mach_target->TaskIsValid() && mach_target->ExceptionPortIsValid()) {
          continue;
        }

      exit_label:
        if (trace_debug_events) {
          SAY("Debugger: Process exit\n");
        }

        OnProcessExit();
        alive = false;
        continue;

      default:
        if (krt != MACH_MSG_SUCCESS) {
          FATAL("mach_msg returned with error code: %d\n", krt);
        }

        break;
    }

    /* mach_exc_server calls catch_mach_exception_raise */
    /* HandleExceptionInternal returns in ret_HandleExceptionInternal */

    boolean_t message_parsed_correctly = mach_exc_server(request_buffer, reply_buffer);
    dbg_continue_needed = true;

    if (!message_parsed_correctly) {
      krt = ((mig_reply_error_t *)reply_buffer)->RetCode;
      FATAL("catch_mach_exception_raise returned with error code: %d\n", krt);
    }

    if (ret_HandleExceptionInternal == DEBUGGER_CRASHED) {
      OnCrashed(&last_exception);
    }

    if (ret_HandleExceptionInternal != DEBUGGER_CONTINUE) {
      return ret_HandleExceptionInternal;
    }

    task_resume(mach_target->Task());
    mach_target->ReplyToException(reply_buffer);
  }

  return DEBUGGER_PROCESS_EXIT;
}

/**
 * Method not used, implementation is needed by the mach_exc_server method.
*/
kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port,
    mach_port_t thread_port,
    mach_port_t task_port,
    exception_type_t exception_type,
    mach_exception_data_t codes,
    mach_msg_type_number_t num_codes) {
  return MACH_RCV_INVALID_TYPE;
}


/**
 * Method not used, implementation is needed by the mach_exc_server method.
 */
kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port,
    exception_type_t exception_type,
    const mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt) {
  return MACH_RCV_INVALID_TYPE;
}

/**
 * Called by mach_exc_server
 *
 * @param exception_port the target_exception_port registered in AttachToProcess() method
 * @param task_port the target_task
*/
kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port,
    mach_port_t thread_port,
    mach_port_t task_port,
    exception_type_t exception_type,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt) {

  memcpy(new_state, old_state, old_stateCnt * sizeof(old_state[0]));
  *new_stateCnt = old_stateCnt;

  Debugger::MachException *mach_exception = new Debugger::MachException(exception_port,
                                                                                  thread_port,
                                                                                  task_port,
                                                                                  exception_type,
                                                                                  code,
                                                                                  codeCnt,
                                                                                  flavor,
                                                                                  new_state,
                                                                                  new_stateCnt);



  class Debugger *dbg = Debugger::task_to_debugger_map[task_port];
  dbg->HandleExceptionInternal(mach_exception);

  if (dbg->dbg_continue_status == KERN_SUCCESS) {
    kern_return_t krt;
    krt = mach_port_deallocate(mach_task_self(), task_port);
    if (krt != KERN_SUCCESS) {
      FATAL("Unable to deallocate task_port, %d\n", krt);
    }

    krt = mach_port_deallocate(mach_task_self(), thread_port);
    if (krt != KERN_SUCCESS) {
      FATAL("Unable to deallocate thread_port, %d\n", krt);
    }
  }

  delete mach_exception;
  return dbg->dbg_continue_status;
}


DebuggerStatus Debugger::Kill() {
  if (mach_target == NULL || !mach_target->TaskIsValid()) {
    return DEBUGGER_PROCESS_EXIT;
  }

  mach_target->Exit();
  kill(mach_target->Pid(), SIGKILL);

  //SIGKILL is not handled, so DebugLoop must return DEBUGGER_PROCESS_EXIT
  dbg_last_status = DebugLoop(0xffffffff);
  if (dbg_last_status != DEBUGGER_PROCESS_EXIT || mach_target->TaskIsValid()) {
    FATAL("Unable to kill the process\n");
  }

  DeleteBreakpoints();

  return dbg_last_status;
}


void Debugger::StartProcess(char *cmd) {
  pid_t pid;
  int status;
  posix_spawnattr_t attr;

  status = posix_spawnattr_init(&attr);
  if (status != 0) {
    FATAL("Unable to init spawnattr");
  }

  status = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
  if (status != 0) {
    FATAL("Unable to set flags in posix_spawnattr_setflags");
  }

  status = posix_spawn(&pid, cmd, NULL, &attr, NULL, NULL);
  if (status != 0) {
    FATAL("Unable to posix_spawn the process: %s\n", strerror(status));
  }

  DeleteBreakpoints();
  mach_target = new MachTarget(pid);
}


void Debugger::AttachToProcess() {
  int ptrace_ret;
  ptrace_ret = ptrace(PT_ATTACHEXC, mach_target->Pid(), 0, 0);
  if (ptrace_ret == -1) {
    FATAL("Unable to ptrace PT_ATTACHEXC to the target process\n");
  }

  task_to_debugger_map[mach_target->Task()] = this;
  dbg_last_status = DEBUGGER_ATTACHED;
}


DebuggerStatus Debugger::Attach(unsigned int pid, uint32_t timeout) {
  attach_mode = true;
  mach_target = new MachTarget(pid);

  AttachToProcess();
  return Continue(timeout);
}


DebuggerStatus Debugger::Run(char *cmd, uint32_t timeout) {
  attach_mode = false;

  StartProcess(cmd);
  AttachToProcess();
  return Continue(timeout);
}


DebuggerStatus Debugger::Continue(uint32_t timeout) {
  if (loop_mode && (dbg_last_status == DEBUGGER_TARGET_END)) {
    dbg_last_status = DEBUGGER_TARGET_START;
    return dbg_last_status;
  }

  dbg_last_status = DebugLoop(timeout);

  if (dbg_last_status == DEBUGGER_PROCESS_EXIT) {
    mach_target->Exit();
    delete mach_target;
  }

  return dbg_last_status;
}


void Debugger::Init(int argc, char **argv) {
  mach_target = NULL;

  attach_mode = false;
  trace_debug_events = false;
  loop_mode = false;
  target_function_defined = false;

  target_module[0] = 0;
  target_method[0] = 0;
  target_offset = 0;
  saved_args = NULL;
  target_num_args = 0;

  dbg_last_status = DEBUGGER_NONE;

  dbg_continue_needed = false;
  request_buffer = (mach_msg_header_t *)malloc(sizeof(union __RequestUnion__catch_mach_exc_subsystem));
  reply_buffer = (mach_msg_header_t *)malloc(sizeof(union __ReplyUnion__catch_mach_exc_subsystem));

  m_dyld_process_info_create =
      (void *(*)(task_t task, uint64_t timestamp, kern_return_t * kernelError))
          dlsym(RTLD_DEFAULT, "_dyld_process_info_create");
  m_dyld_process_info_for_each_image =
      (void (*)(void *info, void (^)(uint64_t machHeaderAddress,
                                     const uuid_t uuid, const char *path)))
          dlsym(RTLD_DEFAULT, "_dyld_process_info_for_each_image");
  m_dyld_process_info_release =
      (void (*)(void *info))dlsym(RTLD_DEFAULT, "_dyld_process_info_release");
  m_dyld_process_info_get_cache = (void (*)(void *info, void *cacheInfo))dlsym(
      RTLD_DEFAULT, "_dyld_process_info_get_cache");
  m_dyld_process_info_get_platform = (uint32_t (*)(void *info))dlsym(
      RTLD_DEFAULT, "_dyld_process_info_get_platform");

  //TO DO parse command line arguments
  char *option;

  trace_debug_events = GetBinaryOption("-trace_debug_events",
                                       argc, argv,
                                       trace_debug_events);

  option = GetOption("-target_module", argc, argv);
  if (option) strncpy(target_module, option, PATH_MAX);

  option = GetOption("-target_method", argc, argv);
  if (option) strncpy(target_method, option, PATH_MAX);

  loop_mode = GetBinaryOption("-loop", argc, argv, loop_mode);

  option = GetOption("-nargs", argc, argv);
  if (option) target_num_args = atoi(option);

  option = GetOption("-target_offset", argc, argv);
  if (option) target_offset = strtoul(option, NULL, 0);

  // check if we are running in persistence mode
  if (target_module[0] || target_offset || target_method[0]) {
    target_function_defined = true;
    if ((target_module[0] == 0) || ((target_offset == 0) && (target_method[0] == 0))) {
      FATAL("target_module and either target_offset or target_method must be specified together\n");
    }
  }

  if (loop_mode && !target_function_defined) {
    FATAL("Target function needs to be defined to use the loop mode\n");
  }

//
//  /**
//   * Add the line below to get debug events on the command line.
//   */
//  trace_debug_events = true;
//
//  /**
//   * Change path to your own target's path.
//   */
//  char path[] = "/Users/aniculae/Library/Developer/Xcode/DerivedData/LLDB-Test-gykqqxdyxchpaualvtozhjmnahbg/Build/Products/Debug/LLDB-Test";
//
//  /**
//   * Change timeout per DebugLoop.
//   */
//  uint32_t timeout = 5000;
//
//  /**
//   * To break when the target function is reached in the target module, add the lines below
//   * and change the target_module and target_method names as wanted, and update target_num_args
//   * accordingly.
//   */
//  target_function_defined = true;
//  strcpy(target_module, path);
//  strcpy(target_method, "__Z1fiiiiiiiii");
//  loop_mode = true;
//  target_num_args = 5;
//
//
//
//  DebuggerStatus dbg_status = Run(path, timeout);
//  printf("DebugLoop returned DebuggerStatus: %d\n", dbg_status);
//
//  if (dbg_status == DEBUGGER_TARGET_START) {
//    dbg_status = Continue(timeout);
//    printf("DebugLoop returned DebuggerStatus %d\n", dbg_status);
//
//    if (dbg_status == DEBUGGER_TARGET_END) {
//      dbg_status = Continue(timeout);
//      printf("DebugLoop returned DebuggerStatus %d\n", dbg_status);
//
//      if (dbg_status == DEBUGGER_TARGET_START) {
//        dbg_status = Continue(timeout);
//        printf("DebugLoop returned DebuggerStatus %d\n", dbg_status);
//      }
//    }
//  }

  if (target_num_args) {
    saved_args = (void **)malloc(target_num_args * sizeof(void *));
  }
}
//
///* TO DO Remove main in the future */
//int main() {
//  DebuggerMacOs dbg;
//  dbg.Init(0, NULL);
//  return 0;
//}

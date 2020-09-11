# TinyInst on macOS

```
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Limitations on macOS

* TinyInst is unable to collect coverage on process exit and requires a target method to be able to collect it.
* TinyInst may not detect the exact time when the target process has exited, and so the `OnProcessExit()` callback might have a maximum delay of 100ms.
* TinyInst on macOS has a `-gmalloc` flag, which enables the g_malloc environment variable when starting up a process. However, please note that this flag is incompatible with the `-target_method` flag.
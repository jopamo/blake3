project('b3sum', 'c',
  version: '1.0.0',
  meson_version: '>=1.2.0',
  default_options: [
    'buildtype=release',
    'c_std=c17',
    'default_library=shared',
  ]
)

fs = import('fs')
cc = meson.get_compiler('c')
debug_sanitize = get_option('debug_sanitize')

if debug_sanitize and cc.get_id() != 'clang'
  error('debug_sanitize option requires clang (set CC=clang when running meson setup)')
endif

project_c_args = []
project_link_args = []
simd_args = []
simd_defines = []
threads_dep = dependency('threads')

# core blake3 sources
blake3_sources = [
  'src/blake3.c',
  'src/blake3_dispatch.c',
  'src/blake3_portable.c',
  'src/blake3_parallel.c',
]

# arch-specific implementations are always compiled
# runtime dispatch in blake3_dispatch.c should pick the best path at runtime
if host_machine.cpu_family() == 'x86_64'
  blake3_sources += [
    'src/blake3_sse2_x86-64_unix.S',
    'src/blake3_sse41_x86-64_unix.S',
    'src/blake3_avx2_x86-64_unix.S',
    'src/blake3_avx512_x86-64_unix.S',
  ]

  # we do NOT inject -mavx2/-mavx512f globally because that would make the whole binary require them
  # keep simd_args empty for portability and let the asm be written with explicit .target/.arch
elif host_machine.cpu_family() in ['arm', 'aarch64']
  blake3_sources += ['src/blake3_neon.c']

  # on aarch64 NEON is baseline, no flag needed
  if host_machine.cpu_family() == 'arm'
    if cc.has_argument('-mfpu=neon')
      simd_args += ['-mfpu=neon']
    endif
  endif
endif

# recommended portable codegen flags
common_opt_args = [
  '-fno-plt',
  '-ffunction-sections', '-fdata-sections',
  '-falign-functions=32',
]

foreach a : common_opt_args
  if cc.has_argument(a)
    project_c_args += [a]
  endif
endforeach

# sanitizers
if debug_sanitize
  sanitize_flags = ['-fsanitize=address', '-fsanitize=undefined']

  foreach flag : sanitize_flags
    if not cc.has_argument(flag)
      error('compiler does not support ' + flag)
    endif
  endforeach

  if not cc.links('int main(void){return 0;}', args: sanitize_flags)
    error('failed to link with address/undefined sanitizers')
  endif

  # we want nice stacks under asan/ubsan
  project_c_args += sanitize_flags + ['-fno-omit-frame-pointer', '-g']
  project_link_args += sanitize_flags

  if cc.get_id() == 'clang'
    if cc.has_link_argument('-shared-libasan')
      project_link_args += ['-shared-libasan']
    endif
    if cc.has_link_argument('-shared-libubsan')
      project_link_args += ['-shared-libubsan']
    endif
  endif
else
  # try thin LTO with clang first, then fallback to -flto
  if cc.get_id() == 'clang'
    if cc.has_argument('-flto=thin') and cc.links('int main(void){return 0;}', args: ['-flto=thin'])
      project_c_args += ['-flto=thin']
      project_link_args += ['-flto=thin']
    elif cc.has_argument('-flto') and cc.links('int main(void){return 0;}', args: ['-flto'])
      project_c_args += ['-flto']
      project_link_args += ['-flto']
    endif
  else
    if cc.has_argument('-flto') and cc.links('int main(void){return 0;}', args: ['-flto'])
      project_c_args += ['-flto']
      project_link_args += ['-flto']
    endif
  endif
endif

# gc-sections helps drop unused SIMD variants from final link
if cc.get_id() in ['gcc', 'clang']
  project_link_args += ['-Wl,--gc-sections']
endif

add_project_arguments(project_c_args, language: 'c')
add_project_link_arguments(project_link_args, language: 'c')

libblake3 = shared_library(
  'blake3',
  blake3_sources,
  version: '1.0.0',
  soversion: '1',
  install: true,
  install_dir: get_option('libdir'),
  c_args: simd_args + simd_defines,
  dependencies: threads_dep
)

b3sum_exe = executable(
  'b3sum',
  ['src/b3sum.c'],
  link_with: libblake3,
  install: true,
  c_args: simd_args + simd_defines,
  override_options: ['b_lundef=false']
)

# install public headers
install_headers('src/blake3.h', subdir: 'b3sum')
install_headers('src/blake3_parallel.h', subdir: 'b3sum')

pkg = import('pkgconfig')
pkg.generate(
  name: 'blake3',
  description: 'BLAKE3 hash function library',
  version: meson.project_version(),
  libraries: libblake3,
  extra_cflags: simd_args,
  install_dir: join_paths(get_option('libdir'), 'pkgconfig')
)

test_parallel = executable(
  'test_parallel',
  ['tests/test_parallel.c'],
  link_with: libblake3,
  c_args: simd_args + simd_defines,
)
test('parallel_hashing', test_parallel)

test_flags_keys = executable(
  'test_flags_keys',
  ['tests/test_flags_keys.c'],
  link_with: libblake3,
  c_args: simd_args + simd_defines,
)
test('flags_keys', test_flags_keys)

test_parallel_extended = executable(
  'test_parallel_extended',
  ['tests/test_parallel_extended.c'],
  link_with: libblake3,
  c_args: simd_args + simd_defines,
)
test('parallel_extended', test_parallel_extended)

test_regressions = executable(
  'test_regressions',
  ['tests/test_regressions.c'],
  link_with: libblake3,
  c_args: simd_args + simd_defines,
)
test('regressions', test_regressions)

test_fault_injection = executable(
  'test_fault_injection',
  ['tests/test_fault_injection.c'],
  c_args: simd_args + simd_defines,
  dependencies: threads_dep
)
test('fault_injection', test_fault_injection)

test_vectors = executable(
  'test_vectors',
  ['tests/test_vectors.c'],
  link_with: libblake3,
  c_args: simd_args + simd_defines,
)
test('vectors', test_vectors)

test_streaming = executable(
  'test_streaming',
  ['tests/test_streaming.c'],
  link_with: libblake3,
  c_args: simd_args + simd_defines,
)
test('streaming', test_streaming)

test_keyed = executable(
  'test_keyed',
  ['tests/test_keyed.c'],
  link_with: libblake3,
  c_args: simd_args + simd_defines,
)
test('keyed', test_keyed)

test('cli',
  find_program('tests/test_cli.sh'),
  depends: [b3sum_exe],
  env: ['MESON_BUILD_ROOT=' + meson.current_build_dir()]
)

summary({
  'SIMD compile args': simd_args,
  'BLAKE3 source files': blake3_sources,
  'Architecture': host_machine.cpu_family(),
  'Sanitizers enabled': debug_sanitize,
  'Project C flags': project_c_args,
  'Project link flags': project_link_args,
})

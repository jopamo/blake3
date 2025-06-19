project('b3sum', 'c',
  version: 'VERSION',
  default_options: ['buildtype=release', 'c_std=c11', 'default_library=shared'])

musl_cc = find_program('musl-gcc', required: get_option('build_static_b3sum'))

cc = musl_cc.found() and get_option('build_static_b3sum') ? musl_cc : meson.get_compiler('c')

simd_args = []
simd_defines = []

blake3_sources = [
  'src/blake3.c',
  'src/blake3_dispatch.c',
  'src/blake3_portable.c',
]

if host_machine.cpu_family() == 'x86_64'
  blake3_sources += [
    'src/blake3_sse2_x86-64_unix.S',
    'src/blake3_sse41_x86-64_unix.S',
    'src/blake3_avx2_x86-64_unix.S',
    'src/blake3_avx512_x86-64_unix.S',
  ]
elif host_machine.cpu_family() == 'arm' or host_machine.cpu_family() == 'aarch64'
  blake3_sources += [
    'src/blake3_neon.c',
  ]
endif

check_simd_prog = find_program('src/check_cpu_features.py')
simd_output = run_command(check_simd_prog, check: true).stdout().strip().splitlines()

sse2_supported = false
sse41_supported = false
avx2_supported = false
avx512_supported = false

foreach line : simd_output
  parts = line.split(':')
  if parts.length() == 2
    feature = parts[0].strip()
    supported = parts[1].strip() == 'Supported'
    if feature == 'sse2'
      sse2_supported = supported
    elif feature == 'sse4.1'
      sse41_supported = supported
    elif feature == 'avx2'
      avx2_supported = supported
    elif feature == 'avx512'
      avx512_supported = supported
    endif
  endif
endforeach

if host_machine.cpu_family() == 'x86_64'
  if sse2_supported
    simd_args += ['-msse2']
  endif

  if sse41_supported
    simd_args += ['-msse4.1']
  endif

  if avx2_supported
    simd_args += ['-mavx2']
  endif

  if avx512_supported
    simd_args += ['-mavx512f']
  endif
elif host_machine.cpu_family() == 'arm' or host_machine.cpu_family() == 'aarch64'
  if cc.has_argument('-mfpu=neon')
    simd_args += ['-mfpu=neon']
  endif
endif

maybe_args = [
  '-march=native', '-mtune=native',
  '-fno-plt',
  '-ffunction-sections', '-fdata-sections',
  '-falign-functions=32',
]

foreach a : maybe_args
  if cc.has_argument(a)
    simd_args += [a]
  endif
endforeach

if cc.get_id() in ['gcc', 'clang']
  add_project_link_arguments('-Wl,--gc-sections', language : 'c')
endif

if cc.has_argument('-flto')
  add_project_arguments('-flto', language : 'c')
  add_project_link_arguments('-flto', language : 'c')
endif

if get_option('build_static_lib')
  static_blake3_lib = static_library('blake3', blake3_sources, c_args: simd_args + simd_defines, install: true)
endif

if get_option('build_shared_lib')
  shared_blake3_lib = shared_library('blake3', blake3_sources, c_args: simd_args + simd_defines, install: true)
  install_symlink('libblake3.so', install_dir: join_paths(get_option('libdir'), 'lib'), pointing_to: shared_blake3_lib.full_path())
endif

if get_option('build_static_b3sum')

  b3sum_c_args = ['-static']
  b3sum_lib = static_blake3_lib
else

  b3sum_c_args = []
  b3sum_lib = shared_blake3_lib
endif

executable('b3sum',
  ['src/b3sum.c'],
  link_with: b3sum_lib,
  dependencies: [],
  install: true,
  c_args: simd_args + simd_defines + b3sum_c_args,
  override_options: ['b_lundef=false', 'b_staticpic=false']
)

install_headers('src/blake3.h', subdir: 'b3sum')

pkg = import('pkgconfig')
pkg.generate(
  name: 'blake3',
  description: 'BLAKE3 hash function library',
  version: meson.project_version(),
  libraries: ['-lblake3'],
  extra_cflags: simd_args + maybe_args,
  install_dir: join_paths(get_option('prefix'), 'lib/pkgconfig')
)

summary({
  'SIMD Arguments': simd_args,
  'BLAKE3 Source Files': blake3_sources,
  'Architecture': host_machine.cpu_family(),
  'SSE2 Enabled': sse2_supported,
  'SSE4.1 Enabled': sse41_supported,
  'AVX2 Enabled': avx2_supported,
  'AVX512 Enabled': avx512_supported,
  'Build Static Library': get_option('build_static_lib'),
  'Build Shared Library': get_option('build_shared_lib'),
  'Build Static b3sum': get_option('build_static_b3sum'),
  'Using musl-gcc for static b3sum': musl_cc.found()
})

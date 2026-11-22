const families = [
  ['OS packages', ['os', 'os-pkgs', 'os-package', 'apk', 'deb', 'dpkg', 'rpm', 'opkg', 'alpm', 'pacman',
    'alpine', 'debian', 'ubuntu', 'rhel', 'centos', 'rocky', 'rockylinux', 'alma', 'almalinux',
    'oracle', 'oraclelinux', 'ol', 'amazon', 'amazonlinux', 'amazon linux', 'amzn', 'photon', 'fedora',
    'suse', 'sles', 'sle', 'opensuse', 'opensuse-leap', 'opensuse-tumbleweed', 'mariner', 'azure',
    'azurelinux', 'wolfi', 'chainguard', 'minimos', 'redhat', 'red-hat', 'redhat-cpe', 'cbl-mariner',
    'arch', 'archlinux', 'arch-linux', 'flathub', 'flatpak', 'bitnami', 'echo', 'echo-linux', 'alma-linux',
    'linux-kernel', 'linux-kernel-module', 'portage', 'gentoo', 'msrc-kb', 'nix']],
  ['.NET', ['.net', 'dotnet', 'nuget', 'dotnet-deps', 'dotnet-deps-json']],
  ['C / C++', ['c++', 'cpp', 'conan', 'vcpkg']],
  ['Dart', ['dart', 'dart-pub', 'pub', 'pubspec']],
  ['Elixir / Erlang', ['elixir', 'erlang', 'erlang-otp', 'otp', 'hex', 'mix', 'mix-lock', 'rebar3']],
  ['Go', ['go', 'golang', 'go-module', 'gobinary', 'gomod', 'go-module-binary']],
  ['Java', ['java', 'java-archive', 'jar', 'war', 'ear', 'maven', 'gradle', 'pom', 'jenkins-plugin',
    'jetbrains-plugin', 'graalvm-native-image']],
  ['JavaScript / TypeScript', ['javascript', 'typescript', 'node', 'node.js', 'node-pkg', 'node-package',
    'npm', 'yarn', 'pnpm', 'bun', 'npm-package', 'package-lock', 'nodejs']],
  ['PHP', ['php', 'composer', 'php-composer', 'php-pear', 'php-pecl', 'pear', 'pecl', 'wordpress-plugin']],
  ['Python', ['python', 'python-package', 'pip', 'pypi', 'pipenv', 'poetry', 'uv', 'conda']],
  ['Ruby', ['ruby', 'gem', 'rubygems', 'bundler', 'gemspec']],
  ['Rust', ['rust', 'rust-crate', 'cargo', 'cargo-auditable', 'crates.io']],
  ['Swift / Objective-C', ['swift', 'swiftpm', 'swift-package-manager', 'cocoapods', 'pod']],
  ['Haskell', ['haskell', 'hackage', 'cabal', 'stack']],
  ['Lua', ['lua', 'lua-rocks', 'luarocks']],
  ['OCaml', ['ocaml', 'opam']],
  ['Perl', ['perl', 'cpan']],
  ['R', ['r', 'cran', 'r-package']],
] as const;

const aliases = new Map<string, string>();
for (const [family, types] of families) {
  for (const type of types) aliases.set(type, family);
}

export function ecosystemGroup(type: string): string {
  return aliases.get(type.trim().toLowerCase()) ?? 'Other';
}

export function sortEcosystems(groups: Iterable<string>): string[] {
  return Array.from(new Set(groups)).sort((left, right) => {
    if (left === right) return 0;
    if (left === 'OS packages' || right === 'Other') return -1;
    if (right === 'OS packages' || left === 'Other') return 1;
    return left.localeCompare(right);
  });
}

export function ecosystemTypes(group: string): string {
  return families.find(([name]) => name === group)?.[1].join(',') ?? '';
}

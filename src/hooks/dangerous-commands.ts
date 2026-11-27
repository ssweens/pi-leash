/**
 * Dangerous command matchers for the permission gate.
 *
 * Built-in dangerous patterns are matched structurally via AST parsing.
 * Each matcher receives the parsed command words and returns a description
 * if the command is dangerous, or undefined if not matched.
 */

import { basename } from "node:path";

export type StructuralMatcher = (words: string[]) => string | undefined;

const KEYWORDS = new Set([
  "then",
  "do",
  "else",
  "elif",
  "if",
  "while",
  "until",
  "{",
  "}",
  "!",
  "(",
  ")",
  "done",
  "fi",
  "esac",
]);
const REDIRECT = /^(?:\d*|&)(?:>>|>&|>\||>|<<<|<<-?|<&|<>|<)/;

/** Wrappers that run the command after them: options that take a value, and positional arguments to skip. */
const WRAPPERS: Record<string, { valued: string[]; positional?: number }> = {
  env: {
    valued: ["-u", "-C", "-S", "--unset", "--chdir", "--split-string"],
  },
  command: { valued: [] },
  builtin: { valued: [] },
  nohup: { valued: [] },
  setsid: { valued: [] },
  exec: { valued: ["-a"] },
  time: { valued: ["-f", "-o", "--format", "--output"] },
  nice: { valued: ["-n", "--adjustment"] },
  ionice: { valued: ["-c", "-n", "-p", "-P", "-u"] },
  stdbuf: { valued: ["-i", "-o", "-e"] },
  timeout: {
    valued: ["-s", "-k", "--signal", "--kill-after"],
    positional: 1,
  },
  xargs: {
    valued: [
      "-n",
      "-I",
      "-L",
      "-P",
      "-s",
      "-d",
      "-E",
      "-a",
      "--max-args",
      "--max-procs",
      "--delimiter",
      "--arg-file",
      "--max-chars",
      "--max-lines",
      "--eof",
    ],
  },
  busybox: { valued: [] },
};

const GIT_VALUED = [
  "-C",
  "-c",
  "--git-dir",
  "--work-tree",
  "--namespace",
  "--super-prefix",
  "--config-env",
  "--attr-source",
];

/** `git -C dir -c k=v push` becomes `git push`: global options removed so subcommand rules see it. */
function gitWords(w: string[]): string[] {
  let i = 1;
  while (w[i]?.startsWith("-") && w[i] !== "--") {
    i += GIT_VALUED.includes(w[i] as string) ? 2 : 1;
  }
  return ["git", ...w.slice(i)];
}

/** Drop env assignments, redirections, shell keywords and wrappers (env, nice, timeout, xargs …) from the front; name by basename. */
export function stripCommandWords(input: string[]): string[] {
  let w = input;
  if (w[0] && /^\{[^{}\s]*,[^{}\s]*\}$/.test(w[0])) {
    w = [...w[0].slice(1, -1).split(","), ...w.slice(1)];
  }
  let i = 0;
  for (;;) {
    const x = w[i];
    if (x === undefined) return [];
    if (
      /^[A-Za-z_][A-Za-z0-9_]*\+=?/.test(x) ||
      /^[A-Za-z_][A-Za-z0-9_]*=/.test(x) ||
      KEYWORDS.has(x)
    ) {
      i++;
    } else if (REDIRECT.test(x)) {
      i += x.replace(REDIRECT, "") ? 1 : 2;
    } else {
      const name = basename(x);
      const spec = WRAPPERS[name];
      if (!spec) {
        return name === "git"
          ? gitWords([name, ...w.slice(i + 1)])
          : [name, ...w.slice(i + 1)];
      }
      i++;
      if (name === "command" && (w[i] === "-v" || w[i] === "-V")) return [];
      while (w[i]?.startsWith("-")) {
        const o = w[i] as string;
        if (o === "--") {
          i++;
          break;
        }
        i += spec.valued.includes(o) ? 2 : 1;
      }
      if (spec.positional && w[i]) i += spec.positional;
    }
  }
}

/** The commands after `-exec`, `-execdir`, `-ok`, `-okdir` in a `find`, each up to its `;` or `+`. */
export function execSegments(w: string[]): string[][] {
  const out: string[][] = [];
  for (let i = 0; i < w.length; i++) {
    if (!["-exec", "-execdir", "-ok", "-okdir"].includes(w[i] as string)) {
      continue;
    }
    let j = i + 1;
    while (j < w.length && w[j] !== ";" && w[j] !== "+") j++;
    out.push(w.slice(i + 1, j));
    i = j;
  }
  return out;
}

/**
 * Helper to check if any word starts with a given prefix.
 */
function hasArg(words: string[], prefix: string): boolean {
  return words.some((w) => w.startsWith(prefix));
}

/**
 * Helper to check if short options contain specific flags.
 * Handles grouped short options like -rf, -fr, -Rfv, etc.
 */
function hasShortFlag(words: string[], flag: string): boolean {
  return words.some(
    (w) =>
      w === `-${flag}` ||
      (w.startsWith("-") && !w.startsWith("--") && w.includes(flag)),
  );
}

/**
 * Helper to check for long options.
 */
function hasLongOption(words: string[], option: string): boolean {
  return words.some((w) => w === `--${option}`);
}

// =============================================================================
// File/Directory Destruction
// =============================================================================

/**
 * rm -rf, rm -r -f, rm --recursive --force, etc.
 * Catches recursive force delete in any form.
 */
const rmMatcher: StructuralMatcher = (words) => {
  if (words[0] !== "rm") return undefined;

  const hasRecursive =
    hasShortFlag(words, "r") ||
    hasShortFlag(words, "R") ||
    hasLongOption(words, "recursive") ||
    hasLongOption(words, "dir");

  const hasForce = hasShortFlag(words, "f") || hasLongOption(words, "force");

  return hasRecursive && hasForce ? "recursive force delete" : undefined;
};

/**
 * find -delete or find -exec rm/shred
 */
const findDeleteMatcher: StructuralMatcher = (words) => {
  if (words[0] !== "find") return undefined;
  const deletes =
    words.includes("-delete") ||
    execSegments(words).some((seg) =>
      ["rm", "shred"].includes(basename(seg[0] ?? "")),
    );
  return deletes ? "find -delete" : undefined;
};

/**
 * shred - secure file/device overwrite
 */
const shredMatcher: StructuralMatcher = (words) => {
  if (words[0] === "shred") return "secure file overwrite";
  return undefined;
};

// =============================================================================
// Privilege Escalation
// =============================================================================

/**
 * sudo - superuser command
 */
const sudoMatcher: StructuralMatcher = (words) => {
  if (words[0] === "sudo") return "superuser command";
  return undefined;
};

/**
 * doas - privilege escalation (OpenBSD-style sudo alternative)
 */
const doasMatcher: StructuralMatcher = (words) => {
  if (words[0] === "doas" || words[0] === "su" || words[0] === "runuser") {
    return "privileged command execution";
  }
  return undefined;
};

/**
 * pkexec - PolicyKit privilege escalation
 */
const pkexecMatcher: StructuralMatcher = (words) => {
  if (words[0] === "pkexec") return "privileged command execution";
  return undefined;
};

// =============================================================================
// Disk/Filesystem Operations
// =============================================================================

/**
 * dd of= - disk write operation
 * Any dd command with an output file is potentially dangerous.
 */
const ddMatcher: StructuralMatcher = (words) => {
  if (words[0] !== "dd") return undefined;
  return hasArg(words, "of=") ? "disk write operation" : undefined;
};

/**
 * mkfs, mkfs.* - filesystem format
 */
const mkfsMatcher: StructuralMatcher = (words) => {
  const cmd = words[0];
  if (cmd === "mkfs" || cmd?.startsWith("mkfs.")) return "filesystem format";
  return undefined;
};

/**
 * wipefs - filesystem signature wipe
 */
const wipefsMatcher: StructuralMatcher = (words) => {
  if (words[0] === "wipefs") return "filesystem signature wipe";
  return undefined;
};

/**
 * blkdiscard - block device discard (destroys data)
 */
const blkdiscardMatcher: StructuralMatcher = (words) => {
  if (words[0] === "blkdiscard") return "block device discard";
  return undefined;
};

// =============================================================================
// Disk Partitioning
// =============================================================================

/**
 * fdisk, sfdisk, cfdisk - disk partitioning
 */
const fdiskMatcher: StructuralMatcher = (words) => {
  const cmd = words[0];
  if (cmd === "fdisk" || cmd === "sfdisk" || cmd === "cfdisk") {
    return "disk partitioning";
  }
  return undefined;
};

/**
 * parted, sgdisk - advanced disk partitioning
 */
const partedMatcher: StructuralMatcher = (words) => {
  const cmd = words[0];
  if (cmd === "parted" || cmd === "sgdisk" || cmd === "diskutil") {
    return "disk partitioning";
  }
  return undefined;
};

// =============================================================================
// Permission Changes
// =============================================================================

/**
 * chmod -R 777, chmod --recursive 777, chmod -R 0777, etc.
 * Insecure recursive world-writable permissions.
 */
const chmodMatcher: StructuralMatcher = (words) => {
  if (words[0] !== "chmod") return undefined;

  const hasRecursive =
    hasShortFlag(words, "R") || hasLongOption(words, "recursive");

  const hasWorldWritable = words.some(
    (w) =>
      w === "777" ||
      w === "0777" ||
      w === "a+rwx" ||
      w === "ugo+rwx" ||
      w === "7777" || // setuid/setgid/sticky + world writable
      w === "1777", // sticky + world writable
  );

  return hasRecursive && hasWorldWritable
    ? "insecure recursive permissions"
    : undefined;
};

/**
 * chown -R, chown --recursive - recursive ownership change
 */
const chownMatcher: StructuralMatcher = (words) => {
  if (words[0] !== "chown") return undefined;

  const hasRecursive =
    hasShortFlag(words, "R") || hasLongOption(words, "recursive");

  return hasRecursive ? "recursive ownership change" : undefined;
};

// =============================================================================
// Container Escape / Dangerous Container Operations
// =============================================================================

/**
 * Docker/Podman dangerous run/create patterns.
 * Flags: --privileged, --pid=host, --network=host, --userns=host,
 *        --uts=host, --ipc=host, -v /:/host, docker socket mounts
 */
const containerMatcher: StructuralMatcher = (words) => {
  const cmd = words[0];
  if (!cmd) return undefined;

  // Match docker or podman commands
  const isDocker = cmd === "docker" || cmd === "podman";
  if (!isDocker) return undefined;

  // Only check run and create commands (not build, pull, etc.)
  const subcommand = words[1];
  if (subcommand !== "run" && subcommand !== "create") return undefined;

  // Check for dangerous flags
  const hasPrivileged = words.some(
    (w) => w === "--privileged" || w.startsWith("--privileged="),
  );

  const hasHostPid = words.some(
    (w) => w === "--pid=host" || w.startsWith("--pid=host"),
  );

  const hasHostNetwork = words.some(
    (w) =>
      w === "--network=host" ||
      w.startsWith("--network=host") ||
      w === "--net=host" ||
      w.startsWith("--net=host"),
  );

  const hasHostUsers = words.some(
    (w) => w === "--userns=host" || w.startsWith("--userns=host"),
  );

  const hasHostUts = words.some(
    (w) => w === "--uts=host" || w.startsWith("--uts=host"),
  );

  const hasHostIpc = words.some(
    (w) => w === "--ipc=host" || w.startsWith("--ipc=host"),
  );

  // Check for root filesystem bind mount
  const hasRootMount = words.some(
    (w, i) =>
      w.startsWith("-v/:") ||
      w.startsWith("-v/=>") ||
      w.startsWith("--volume=/:") ||
      w.startsWith("--mount=type=bind,source=/,") ||
      /^--mount=.*source=\/(,|$)/.test(w) ||
      (/^(-v|--volume)$/.test(w) && /^\/:/.test(words[i + 1] ?? "")),
  );

  // Check for docker socket mount
  const hasDockerSocket = words.some(
    (w) =>
      w.includes("/var/run/docker.sock") ||
      w.includes("/run/docker.sock") ||
      w.includes("/var/run/podman.sock") ||
      w.includes("/run/podman.sock"),
  );

  if (hasPrivileged) return "container with privileged mode";
  if (hasHostPid) return "container with host PID namespace";
  if (hasHostNetwork) return "container with host network";
  if (hasHostUsers) return "container with host user namespace";
  if (hasHostUts) return "container with host UTS namespace";
  if (hasHostIpc) return "container with host IPC";
  if (hasRootMount) return "container with root filesystem mount";
  if (hasDockerSocket) return "container with docker socket access";

  return undefined;
};

// =============================================================================
// Version Control
// =============================================================================

/**
 * git checkout - branch switch or discard uncommitted changes
 */
const gitCheckoutMatcher: StructuralMatcher = (words) => {
  if (words[0] !== "git") return undefined;
  return words[1] === "checkout"
    ? "branch switch or discard uncommitted changes"
    : undefined;
};

/**
 * git reset - undo commits or discard staged/unstaged changes (destructive)
 */
const gitResetMatcher: StructuralMatcher = (words) => {
  if (words[0] !== "git") return undefined;
  return words[1] === "reset"
    ? "undo commits or discard staged/unstaged changes"
    : undefined;
};

/**
 * git clean - delete untracked files
 */
const gitCleanMatcher: StructuralMatcher = (words) => {
  if (words[0] !== "git" || words[1] !== "clean") return undefined;
  return hasShortFlag(words, "f") ||
    hasLongOption(words, "force") ||
    hasShortFlag(words, "x") ||
    hasShortFlag(words, "d")
    ? "git clean (deletes untracked files)"
    : undefined;
};

/**
 * git push --force / --force-with-lease / --mirror / --delete / +refspec
 */
const gitPushForceMatcher: StructuralMatcher = (words) => {
  if (words[0] !== "git" || words[1] !== "push") return undefined;
  const isForce =
    hasShortFlag(words, "f") ||
    hasLongOption(words, "force") ||
    hasLongOption(words, "force-with-lease") ||
    hasLongOption(words, "mirror") ||
    hasLongOption(words, "delete") ||
    words.slice(2).some((x) => x.startsWith("--force") || /^\+\S/.test(x));
  return isForce ? "git force push" : undefined;
};

const RAW_BUILTIN_MATCHERS: StructuralMatcher[] = [
  // Destruction (highest priority)
  rmMatcher,
  findDeleteMatcher,
  shredMatcher,

  // Privilege escalation
  sudoMatcher,
  doasMatcher,
  pkexecMatcher,

  // Disk/filesystem operations
  ddMatcher,
  mkfsMatcher,
  wipefsMatcher,
  blkdiscardMatcher,
  fdiskMatcher,
  partedMatcher,

  // Permission changes
  chmodMatcher,
  chownMatcher,

  // Container escapes
  containerMatcher,

  // Version control
  gitCheckoutMatcher,
  gitResetMatcher,
  gitCleanMatcher,
  gitPushForceMatcher,
];

/**
 * All built-in dangerous command matchers (wrapped with command/wrapper normalization).
 * Order matters - earlier matchers take precedence if multiple match.
 */
export const BUILTIN_MATCHERS: StructuralMatcher[] = RAW_BUILTIN_MATCHERS.map(
  (matcher) => (words) => matcher(stripCommandWords(words)),
);

/**
 * Keywords for each built-in matcher, used for deduplication against
 * compiled substring patterns. When structural parsing succeeds, substring
 * fallback is skipped for these patterns to avoid false positives.
 */
export const BUILTIN_KEYWORD_PATTERNS = new Set([
  "rm -rf",
  "sudo",
  "dd of=",
  "mkfs.",
  "chmod -R 777",
  "chown -R",
  "doas",
  "pkexec",
  "shred",
  "wipefs",
  "blkdiscard",
  "fdisk",
  "parted",
  "docker run --privileged",
  "git checkout",
  "git reset",
]);

/**
 * Match a command against all built-in dangerous patterns.
 * Returns the first match found, or undefined if no match.
 */
export function matchDangerousCommand(
  words: string[],
): { description: string; pattern: string } | undefined {
  const stripped = stripCommandWords(words);
  for (const matcher of BUILTIN_MATCHERS) {
    const description = matcher(words);
    if (description) {
      const pattern = stripped[0] ?? words[0] ?? "unknown";
      return { description, pattern };
    }
  }
  return undefined;
}

const ANSI_ESCAPES: Record<string, string> = {
  n: "\n",
  t: "\t",
  r: "\r",
  a: "\x07",
  b: "\b",
  e: "\x1b",
  E: "\x1b",
  f: "\f",
  v: "\v",
  "\\": "\\",
  "'": "'",
  '"': '"',
};
const IFS_REF = /^\$(?:\{IFS[^}]*\}|IFS(?![A-Za-z0-9_]))/;

/** Words of one simple command, quotes removed. `$'…'` is decoded; `$IFS` and `${IFS}` outside quotes split words. */
function tokenizeWords(text: string): string[] {
  const out: string[] = [];
  let cur = "";
  let any = false;
  let quote: string | undefined;
  const end = () => {
    if (any || cur) out.push(cur);
    cur = "";
    any = false;
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (quote === "$'") {
      if (c === "'") quote = undefined;
      else if (c === "\\" && i + 1 < text.length) {
        const n = text[++i] as string;
        const hex =
          n === "x" ? /^[0-9a-fA-F]{1,2}/.exec(text.slice(i + 1)) : null;
        const oct = /^[0-7]/.test(n) ? /^[0-7]{1,3}/.exec(text.slice(i)) : null;
        if (hex) {
          cur += String.fromCharCode(Number.parseInt(hex[0], 16));
          i += hex[0].length;
        } else if (oct) {
          cur += String.fromCharCode(Number.parseInt(oct[0], 8));
          i += oct[0].length - 1;
        } else cur += ANSI_ESCAPES[n] ?? n;
      } else cur += c;
    } else if (quote) {
      if (c === quote) quote = undefined;
      else if (c === "\\" && quote === '"' && i + 1 < text.length)
        cur += text[++i];
      else cur += c;
    } else if (c === "$" && text[i + 1] === "'") {
      quote = "$'";
      any = true;
      i++;
    } else if (c === "$" && text[i + 1] === '"') {
      quote = '"';
      any = true;
      i++;
    } else if (c === "$" && IFS_REF.test(text.slice(i))) {
      end();
      const match = IFS_REF.exec(text.slice(i));
      if (match) i += match[0].length - 1;
    } else if (c === "'" || c === '"') {
      quote = c;
      any = true;
    } else if (c === "\\" && i + 1 < text.length) {
      cur += text[++i];
      any = true;
    } else if (/\s/.test(c)) end();
    else {
      cur += c;
      any = true;
    }
  }
  end();
  return out;
}

export interface SimpleCommandSpan {
  text: string;
  words: string[];
  after: string;
  main?: boolean;
  sub?: boolean;
  data?: boolean;
  code?: boolean;
  heredocs?: { owner: number; quoted: boolean }[];
}

const HEREDOC_DATA =
  /^(?:cat|tee|python[0-9.]*|perl|ruby|node|php|lua|sed|jq|sqlite3|patch|tr|sort|wc|head|tail|base64|grep)$/;
const SHELL = /^(?:ba|z|da|k|a|mk)?sh$/;

/** Command strings a command runs: `eval` arguments, a shell's `-c` string (any flag cluster containing c), `env -S`. */
function nestedTexts(raw: string[], w: string[]): string[] {
  const out: string[] = [];
  if (w[0] === "eval" && w.length > 1) out.push(w.slice(1).join(" "));
  if (w[0] && SHELL.test(w[0])) {
    const i = w.findIndex(
      (x, k) => k > 0 && /^[-+][A-Za-z]*c[A-Za-z]*$/.test(x),
    );
    if (i > 0 && w[i + 1] !== undefined) out.push(w[i + 1] as string);
  }
  const env = raw.findIndex((x) => basename(x) === "env");
  if (env >= 0) {
    raw.forEach((x, k) => {
      if (k <= env) return;
      if ((x === "-S" || x === "--split-string") && raw[k + 1] !== undefined)
        out.push(raw[k + 1] as string);
      else if (/^-S./.test(x)) out.push(x.slice(2));
      else if (x.startsWith("--split-string=")) out.push(x.slice(15));
    });
  }
  return out;
}

/**
 * Split a command line into simple commands on ; & && || | newlines, and open subshells ($( ), backticks, parentheses),
 * then add what they run: `sh -c`/`bash -lc`/`eval` strings, `find -exec` commands.
 */
export function simpleCommands(
  command: string,
  depth = 0,
  text = false,
): SimpleCommandSpan[] {
  return parseCommands(command, depth, text).simples;
}

function parseCommands(
  command: string,
  depth = 0,
  text = false,
): { simples: SimpleCommandSpan[]; unsafeTrack: boolean } {
  const out: SimpleCommandSpan[] = [];
  let cur = "";
  let quote: string | undefined;
  let ansi = false;
  let condDepth = -1;
  const inCond = () => condDepth >= 0 && nest === condDepth;
  const quotes: { quote: string | undefined; ansi: boolean; arith?: boolean }[] =
    [];
  let op = "";
  let nest = 0;
  let tick = false;
  let unsafeTrack = false;
  const real: boolean[] = [];
  let lineStart = 0;
  const pending: {
    delim: string;
    dash: boolean;
    quoted: boolean;
    owner: number;
  }[] = [];
  const flush = (next: string, cut = false) => {
    const trimmed = cur.trim();
    cur = "";
    if (trimmed) {
      out.push({
        text: trimmed,
        words: tokenizeWords(trimmed),
        after: op,
        main: depth === 0,
        sub: cut || nest > 0,
        code: real.includes(true),
      });
    }
    op = next;
  };
  const bodies = (from: number): number => {
    const found: { h: (typeof pending)[number]; text: string }[] = [];
    let pos = from;
    for (const h of pending) {
      const lines: string[] = [];
      let done = false;
      while (pos <= command.length && !done) {
        let e = command.indexOf("\n", pos);
        if (e < 0) e = command.length;
        const line = command.slice(pos, e);
        pos = e + 1;
        if ((h.dash ? line.replace(/^\t+/, "") : line) === h.delim) done = true;
        else lines.push(line);
      }
      if (!done) return from;
      found.push({ h, text: lines.join("\n") });
    }
    const line = out.slice(lineStart);
    for (const { h, text: bodyText } of found) {
      const owner = out[h.owner];
      const piped = line.some(
        (x, k) => lineStart + k > h.owner && x.after === "|",
      );
      const data =
        Boolean(owner) &&
        HEREDOC_DATA.test(stripCommandWords(owner?.words ?? [])[0] ?? "") &&
        !piped;
      const ref =
        !data && !piped && owner
          ? { owner: h.owner, quoted: h.quoted }
          : undefined;
      for (const x of parseCommands(bodyText, depth, !h.quoted).simples) {
        out.push({
          ...x,
          main: false,
          sub: true,
          data: x.data || (data && (h.quoted || x.code === false)),
          ...(ref ? { heredocs: [...(x.heredocs ?? []), ref] } : {}),
        });
      }
    }
    return pos;
  };
  for (let i = 0; i < command.length; i++) {
    const c = command[i] as string;
    if (quote) {
      cur += c;
      if (c === "\\" && (quote === '"' || ansi)) cur += command[++i] ?? "";
      else if (c === quote) quote = undefined;
      else if (
        quote === '"' &&
        (c === "`" || (c === "$" && command[i + 1] === "("))
      ) {
        flush(op, true);
        if (c === "$") {
          i++;
          quotes.push({ quote, ansi });
          quote = undefined;
          ansi = false;
        }
        nest++;
        real.push(true);
      }
      continue;
    }
    if (c === "\\") cur += c + (command[++i] ?? "");
    else if (
      c === "#" &&
      !text &&
      (i === 0 || /[\s;|&()]/.test(command[i - 1] as string))
    ) {
      while (i + 1 < command.length && command[i + 1] !== "\n") i++;
    } else if (c === "$" && command[i + 1] === "'") {
      quote = "'";
      ansi = true;
      cur += "$'";
      i++;
    } else if (c === "'" || c === '"') {
      quote = c;
      ansi = false;
      cur += c;
    } else if (
      condDepth < 0 &&
      command.startsWith("[[", i) &&
      (i === 0 || /[\s;|&(]/.test(command[i - 1] as string)) &&
      /[\s]/.test(command[i + 2] ?? "")
    ) {
      condDepth = nest;
      cur += "[[";
      i++;
    } else if (
      inCond() &&
      command.startsWith("]]", i) &&
      /[\s]/.test(command[i - 1] ?? "") &&
      (i + 2 === command.length || /[\s;|&)]/.test(command[i + 2] as string))
    ) {
      condDepth = -1;
      cur += "]]";
      i++;
    } else if (
      c === "<" &&
      command[i + 1] === "<" &&
      command[i - 1] !== "<" &&
      command[i + 2] !== "<" &&
      !quotes.some((q) => q.arith) &&
      !/^\s*(?:let\b|\(\()/.test(cur)
    ) {
      const m = /^<<(-?)[ \t]*(?:'([^']*)'|"([^"]*)"|([^\s;&|()<>'"]+))/.exec(
        command.slice(i),
      );
      if (m) {
        const delimRaw = m[2] ?? m[3] ?? (m[4] as string);
        pending.push({
          delim: delimRaw.replace(/\\/g, ""),
          dash: Boolean(m[1]),
          quoted: m[4] === undefined || m[4].includes("\\"),
          owner: out.length,
        });
      }
      cur += "<<";
      i++;
    } else if (c === "$" && command[i + 1] === "(") {
      flush(op, true);
      i++;
      quotes.push({
        quote: undefined,
        ansi: false,
        arith: command[i + 1] === "(",
      });
      nest++;
      real.push(true);
    } else if (c === "`") {
      flush(op, true);
      tick = !tick;
      nest += tick ? 1 : -1;
      if (tick) real.push(true);
      else real.pop();
    } else if (c === "(" && !inCond()) {
      if (
        !text &&
        !real.includes(true) &&
        /^\(\s*\)/.test(command.slice(i)) &&
        command[i - 1] !== "(" &&
        command[i + 1] !== "(" &&
        !/[<>=(]$/.test(cur.trim())
      ) {
        unsafeTrack = true;
      }
      flush(op, true);
      quotes.push({
        quote: undefined,
        ansi: false,
        arith: command[i + 1] === "(" || command[i - 1] === "(",
      });
      nest++;
      real.push(!text || real[real.length - 1] === true);
    } else if (c === ")" && !inCond()) {
      flush(op, true);
      if (nest) nest--;
      real.pop();
      const prev = quotes.pop();
      if (prev) {
        quote = prev.quote;
        ansi = prev.ansi;
      }
    } else if (c === "\n") {
      condDepth = -1;
      flush(";");
      if (pending.length) i = bodies(i + 1) - 1;
      pending.length = 0;
      lineStart = out.length;
    } else if (c === ";") {
      condDepth = -1;
      flush(";");
    } else if ((c === "&" || c === "|") && !inCond()) {
      const two = command[i + 1] === c;
      const pipeBoth = c === "|" && command[i + 1] === "&";
      if (two || pipeBoth) i++;
      else if (
        c === "&" &&
        (command[i - 1] === ">" ||
          command[i - 1] === "<" ||
          command[i + 1] === ">")
      ) {
        cur += c;
        continue;
      } else if (c === "&" && !real.includes(true)) {
        unsafeTrack = true;
      }
      flush(pipeBoth || (c === "|" && !two) ? "|" : two ? c + c : ";");
    } else cur += c;
  }
  flush("");
  if (depth < 4) {
    for (const s of [...out]) {
      const w = stripCommandWords(s.words);
      if (w[0] === "find") {
        for (const seg of execSegments(w)) {
          if (seg.length)
            out.push({ text: seg.join(" "), words: seg, after: "" });
        }
      }
    }
    for (const s of [...out]) {
      for (const nested of nestedTexts(s.words, stripCommandWords(s.words))) {
        out.push(...parseCommands(nested, depth + 1).simples);
      }
    }
  }
  return { simples: out, unsafeTrack };
}

const LITERAL =
  /^([A-Za-z_][A-Za-z0-9_]*)=(?:'([^']*)'|"([^"$`\\!]*)"|([^\s"'$`\\;&|()<>*?[\]{}~!#^]+))$/;
const SETTERS = new Set([
  "eval",
  "source",
  ".",
  "read",
  "declare",
  "typeset",
  "local",
  "readonly",
  "unset",
  "getopts",
  "mapfile",
  "readarray",
  "let",
  "trap",
  "shopt",
  "enable",
  "coproc",
]);
const CONTROL = new Set([
  "if",
  "then",
  "else",
  "elif",
  "fi",
  "for",
  "while",
  "until",
  "do",
  "done",
  "case",
  "esac",
  "select",
  "function",
  "[[",
]);
const OPAQUE =
  /^(?:perl|python[0-9.]*|ruby|node|php|lua|awk|gawk|parallel|watch|script|expect|osascript|tclsh)$/;
const DANGER =
  /\b(?:rm\s+(?:-\S*[rRf]|--)|sudo|doas|pkexec|mkfs|shred|dd\s[^|;&]*of=|git\s+(?:\S+\s+)*(?:reset|clean|push)|diskutil|wipefs|chmod\s+-\S*R|chown\s+-\S*R)\b/;

const mentions = (name: string, text: string) =>
  new RegExp(`(?:^|[\\s;&|()])${name}\\+?=`).test(text);

/**
 * Parse `command` and resolve top-level literal `$VAR` command names (plus any nested `sh -c`/`eval`/`find -exec` or `HEREDOC_DATA` bodies unlocked by them).
 */
function resolveSimples(command: string): SimpleCommandSpan[] {
  const { simples, unsafeTrack } = parseCommands(command);
  const track =
    !unsafeTrack &&
    !simples.some((x) => {
      if (!x.main || x.code) return false;
      const sw = stripCommandWords(x.words);
      return (
        x.words[0] === "function" ||
        sw[0] === "function" ||
        SETTERS.has(sw[0] ?? "") ||
        (sw[0] === "printf" && sw.includes("-v")) ||
        x.words.some((w) => /^IFS\+?=/.test(w))
      );
    });
  const lits = new Map<string, string>();
  const expandVars = (str: string) =>
    str.replace(
      /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g,
      (raw, a, b) => {
        const val = lits.get((a ?? b) as string);
        return val !== undefined && !/[\s"'$`\\;&|()<>*?[\]{}~!#^]/.test(val)
          ? val
          : raw;
      },
    );
  const resolved: SimpleCommandSpan[] = [];
  const extra: SimpleCommandSpan[] = [];
  let seenControl = false;
  for (let i = 0; i < simples.length; i++) {
    const s0 = simples[i] as SimpleCommandSpan;
    let s = s0;
    let expandedCommand = false;
    if (track && s0.main) {
      const sw0 = stripCommandWords(s0.words);
      if (
        !s0.code &&
        (CONTROL.has(s0.words[0] ?? "") || CONTROL.has(sw0[0] ?? ""))
      ) {
        seenControl = true;
        for (const rest of simples.slice(i)) {
          for (let k = 0; k < rest.words.length; k++) {
            const kw = rest.words[k];
            const nextW = rest.words[k + 1];
            if ((kw === "for" || kw === "select") && nextW) {
              lits.delete(nextW);
            }
          }
          for (const name of [...lits.keys()]) {
            if (mentions(name, rest.text)) lits.delete(name);
          }
        }
        if (
          s0.words[0] === "for" &&
          s0.words[1] &&
          s0.words[2] === "in" &&
          s0.words.length > 3
        ) {
          const varName = s0.words[1];
          const items = s0.words.slice(3).map(expandVars);
          const base = items[0] ? basename(items[0]) : "";
          if (
            base &&
            items.every(
              (it) =>
                Boolean(it) &&
                !/[\s"'$`\\;&|()<>*?[\]{}~!#^]/.test(it) &&
                basename(it) === base,
            ) &&
            !simples.slice(i + 1).some((rest) => mentions(varName, rest.text))
          ) {
            lits.set(varName, items[0] as string);
          }
        }
      }
      const assignText = s0.text.replace(/^export\s+/, "");
      const expanded =
        /^[A-Za-z_][A-Za-z0-9_]*=/.test(assignText) && !assignText.includes("'")
          ? expandVars(assignText)
          : assignText;
      const m = LITERAL.exec(expanded);
      const set =
        !seenControl &&
        m &&
        !s0.sub &&
        (s0.after === "" || s0.after === ";") &&
        simples[i + 1]?.after !== "|"
          ? m
          : undefined;
      for (const name of [...lits.keys()]) {
        if (!(set && set[1] === name) && mentions(name, s0.text)) {
          lits.delete(name);
        }
      }
      const v =
        /^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$/.exec(
          stripCommandWords(s0.words)[0] ?? "",
        );
      const varName = v ? (v[1] ?? v[2]) : undefined;
      const lit = varName ? lits.get(varName) : undefined;
      if (lit !== undefined && varName !== undefined) {
        const bare =
          !/[\s*?[\]{}~!#^]/.test(lit) ||
          new RegExp(`(?:^|\\s)"\\$\\{?${varName}\\}?"(?:\\s|$|[<>;&|])`).test(
            s0.text,
          );
        const firstStripped = stripCommandWords(s0.words)[0];
        const k = s0.words.findIndex(
          (x, n) =>
            x === firstStripped &&
            stripCommandWords(
              s0.words.map((y, j) => (j === n ? lit : y)),
            )[0] !== x,
        );
        if (bare && k >= 0) {
          s = { ...s0, words: s0.words.map((y, j) => (j === k ? lit : y)) };
          expandedCommand = true;
        }
      }
      if (set) {
        lits.set(set[1] as string, (set[2] ?? set[3] ?? set[4]) as string);
      }
    }
    if (
      !s.data &&
      s.heredocs?.some(
        (h) =>
          (h.quoted || s.code === false) &&
          HEREDOC_DATA.test(
            stripCommandWords(resolved[h.owner]?.words ?? [])[0] ?? "",
          ),
      )
    ) {
      s = { ...s, data: true };
    }
    resolved.push(s);
    if (expandedCommand) {
      const w = stripCommandWords(s.words);
      if (w[0] === "find") {
        for (const seg of execSegments(w)) {
          if (seg.length)
            extra.push({ text: seg.join(" "), words: seg, after: "" });
        }
      }
      for (const nested of nestedTexts(s.words, w)) {
        extra.push(...parseCommands(nested, 1).simples);
      }
    }
  }
  return [...resolved, ...extra];
}

/**
 * Evaluate all simple commands in `command` (including `eval`, `sh -c`, `env -S`, `find -exec`,
 * literal top-level `$VAR` tracking, `pipe-to-shell`, `dynamic-command`, and `indirect-exec`).
 */
export function collectSimpleCommandMatches(
  command: string,
): { description: string }[] {
  const out: { description: string }[] = [];
  const simples = resolveSimples(command);
  simples.forEach((s, i) => {
    const w = stripCommandWords(s.words);
    for (const matcher of RAW_BUILTIN_MATCHERS) {
      const description = matcher(w);
      if (description) out.push({ description });
    }
    if (
      !s.data &&
      /^\$[A-Za-z_@*#?0-9{]/.test(w[0] ?? "") &&
      !(w[0] ?? "").includes("/")
    ) {
      out.push({ description: "command name comes from a variable" });
    }
    if (OPAQUE.test(w[0] ?? "") && DANGER.test(s.text)) {
      out.push({ description: "runs code that mentions a dangerous command" });
    }
    const prev = i > 0 ? stripCommandWords(simples[i - 1]?.words ?? []) : [];
    const target = w[0] === "sudo" ? stripCommandWords(w.slice(1)) : w;
    if (
      s.after === "|" &&
      /^(curl|wget|fetch)$/.test(prev[0] ?? "") &&
      target[0] &&
      SHELL.test(target[0])
    ) {
      out.push({ description: "download piped into a shell" });
    }
  });
  return out;
}

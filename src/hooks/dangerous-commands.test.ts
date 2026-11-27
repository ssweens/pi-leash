import { describe, expect, it } from "vitest";
import {
  BUILTIN_MATCHERS,
  collectSimpleCommandMatches,
  matchDangerousCommand,
} from "./dangerous-commands";

/**
 * Helper to run all matchers against a command string.
 * Returns the first match description, or undefined if none match.
 */
function findMatch(words: string[]): string | undefined {
  for (const matcher of BUILTIN_MATCHERS) {
    const result = matcher(words);
    if (result) return result;
  }
  return undefined;
}

describe("rm matcher", () => {
  it("matches rm -rf", () => {
    expect(findMatch(["rm", "-rf", "/tmp/test"])).toBe(
      "recursive force delete",
    );
  });

  it("matches rm -fr (reversed flags)", () => {
    expect(findMatch(["rm", "-fr", "/tmp/test"])).toBe(
      "recursive force delete",
    );
  });

  it("matches rm -r -f (separate flags)", () => {
    expect(findMatch(["rm", "-r", "-f", "/tmp/test"])).toBe(
      "recursive force delete",
    );
  });

  it("matches rm --recursive --force (long options)", () => {
    expect(findMatch(["rm", "--recursive", "--force", "/tmp/test"])).toBe(
      "recursive force delete",
    );
  });

  it("matches rm --force --recursive (reversed long options)", () => {
    expect(findMatch(["rm", "--force", "--recursive", "/tmp/test"])).toBe(
      "recursive force delete",
    );
  });

  it("matches rm -Rfv (grouped with extra flags)", () => {
    expect(findMatch(["rm", "-Rfv", "/tmp/test"])).toBe(
      "recursive force delete",
    );
  });

  it("does not match rm -r (no force)", () => {
    expect(findMatch(["rm", "-r", "/tmp/test"])).toBeUndefined();
  });

  it("does not match rm -f (no recursive)", () => {
    expect(findMatch(["rm", "-f", "/tmp/test"])).toBeUndefined();
  });

  it("does not match echo rm -rf", () => {
    expect(findMatch(["echo", "rm", "-rf", "/"])).toBeUndefined();
  });
});

describe("sudo matcher", () => {
  it("matches sudo", () => {
    expect(findMatch(["sudo", "apt", "update"])).toBe("superuser command");
  });

  it("matches sudo at start only", () => {
    expect(findMatch(["echo", "sudo", "something"])).toBeUndefined();
  });
});

describe("doas matcher", () => {
  it("matches doas", () => {
    expect(findMatch(["doas", "pkg_add", "vim"])).toBe(
      "privileged command execution",
    );
  });
});

describe("pkexec matcher", () => {
  it("matches pkexec", () => {
    expect(findMatch(["pkexec", "apt", "install", "firefox"])).toBe(
      "privileged command execution",
    );
  });
});

describe("dd matcher", () => {
  it("matches dd with of= (output file)", () => {
    expect(findMatch(["dd", "if=/dev/zero", "of=/dev/sda"])).toBe(
      "disk write operation",
    );
  });

  it("matches dd with of= in any order", () => {
    expect(findMatch(["dd", "of=/dev/sda", "if=/dev/zero"])).toBe(
      "disk write operation",
    );
  });

  it("matches dd with progress and of=", () => {
    expect(
      findMatch(["dd", "status=progress", "of=/dev/sdb", "if=image.img"]),
    ).toBe("disk write operation");
  });

  it("does not match dd with only if= (read-only)", () => {
    expect(findMatch(["dd", "if=/dev/sda"])).toBeUndefined();
  });
});

describe("mkfs matcher", () => {
  it("matches mkfs.ext4", () => {
    expect(findMatch(["mkfs.ext4", "/dev/sda1"])).toBe("filesystem format");
  });

  it("matches mkfs.xfs", () => {
    expect(findMatch(["mkfs.xfs", "/dev/sdb1"])).toBe("filesystem format");
  });

  it("matches plain mkfs", () => {
    expect(findMatch(["mkfs", "/dev/sda1"])).toBe("filesystem format");
  });

  it("matches mkfs.vfat", () => {
    expect(findMatch(["mkfs.vfat", "/dev/sdc1"])).toBe("filesystem format");
  });
});

describe("shred matcher", () => {
  it("matches shred", () => {
    expect(findMatch(["shred", "-u", "secret.txt"])).toBe(
      "secure file overwrite",
    );
  });
});

describe("wipefs matcher", () => {
  it("matches wipefs", () => {
    expect(findMatch(["wipefs", "-a", "/dev/sda"])).toBe(
      "filesystem signature wipe",
    );
  });
});

describe("blkdiscard matcher", () => {
  it("matches blkdiscard", () => {
    expect(findMatch(["blkdiscard", "/dev/nvme0n1"])).toBe(
      "block device discard",
    );
  });
});

describe("fdisk matcher", () => {
  it("matches fdisk", () => {
    expect(findMatch(["fdisk", "/dev/sda"])).toBe("disk partitioning");
  });

  it("matches sfdisk", () => {
    expect(findMatch(["sfdisk", "/dev/sda"])).toBe("disk partitioning");
  });

  it("matches cfdisk", () => {
    expect(findMatch(["cfdisk", "/dev/sda"])).toBe("disk partitioning");
  });
});

describe("parted matcher", () => {
  it("matches parted", () => {
    expect(findMatch(["parted", "/dev/sda"])).toBe("disk partitioning");
  });

  it("matches sgdisk", () => {
    expect(findMatch(["sgdisk", "-l", "/dev/sda"])).toBe("disk partitioning");
  });
});

describe("chmod matcher", () => {
  it("matches chmod -R 777", () => {
    expect(findMatch(["chmod", "-R", "777", "/tmp"])).toBe(
      "insecure recursive permissions",
    );
  });

  it("matches chmod --recursive 777", () => {
    expect(findMatch(["chmod", "--recursive", "777", "/tmp"])).toBe(
      "insecure recursive permissions",
    );
  });

  it("matches chmod -R 0777", () => {
    expect(findMatch(["chmod", "-R", "0777", "/tmp"])).toBe(
      "insecure recursive permissions",
    );
  });

  it("matches chmod -R a+rwx", () => {
    expect(findMatch(["chmod", "-R", "a+rwx", "/tmp"])).toBe(
      "insecure recursive permissions",
    );
  });

  it("matches chmod -R ugo+rwx", () => {
    expect(findMatch(["chmod", "-R", "ugo+rwx", "/tmp"])).toBe(
      "insecure recursive permissions",
    );
  });

  it("does not match chmod 755 (not world-writable)", () => {
    expect(findMatch(["chmod", "755", "file"])).toBeUndefined();
  });

  it("does not match chmod -R 755 (not world-writable)", () => {
    expect(findMatch(["chmod", "-R", "755", "/tmp"])).toBeUndefined();
  });
});

describe("chown matcher", () => {
  it("matches chown -R", () => {
    expect(findMatch(["chown", "-R", "user:group", "/tmp"])).toBe(
      "recursive ownership change",
    );
  });

  it("matches chown --recursive", () => {
    expect(findMatch(["chown", "--recursive", "user", "/tmp"])).toBe(
      "recursive ownership change",
    );
  });

  it("does not match chown without -R", () => {
    expect(findMatch(["chown", "user:group", "/tmp/file"])).toBeUndefined();
  });
});

describe("container matcher (docker/podman)", () => {
  describe("docker", () => {
    it("matches docker run --privileged", () => {
      expect(findMatch(["docker", "run", "--privileged", "alpine"])).toBe(
        "container with privileged mode",
      );
    });

    it("matches docker run --pid=host", () => {
      expect(findMatch(["docker", "run", "--pid=host", "alpine"])).toBe(
        "container with host PID namespace",
      );
    });

    it("matches docker run --network=host", () => {
      expect(findMatch(["docker", "run", "--network=host", "alpine"])).toBe(
        "container with host network",
      );
    });

    it("matches docker run --userns=host", () => {
      expect(findMatch(["docker", "run", "--userns=host", "alpine"])).toBe(
        "container with host user namespace",
      );
    });

    it("matches docker run with root mount", () => {
      expect(findMatch(["docker", "run", "-v/:/host", "alpine"])).toBe(
        "container with root filesystem mount",
      );
    });

    it("matches docker run with docker socket", () => {
      expect(
        findMatch([
          "docker",
          "run",
          "-v",
          "/var/run/docker.sock:/var/run/docker.sock",
          "alpine",
        ]),
      ).toBe("container with docker socket access");
    });

    it("does not match docker build", () => {
      expect(
        findMatch(["docker", "build", "-t", "myimage", "."]),
      ).toBeUndefined();
    });

    it("does not match docker run without dangerous flags", () => {
      expect(
        findMatch(["docker", "run", "alpine", "echo", "hello"]),
      ).toBeUndefined();
    });
  });

  describe("podman", () => {
    it("matches podman run --privileged", () => {
      expect(findMatch(["podman", "run", "--privileged", "alpine"])).toBe(
        "container with privileged mode",
      );
    });

    it("matches podman create --privileged", () => {
      expect(findMatch(["podman", "create", "--privileged", "alpine"])).toBe(
        "container with privileged mode",
      );
    });
  });
});

describe("git checkout matcher", () => {
  it("matches git checkout", () => {
    expect(findMatch(["git", "checkout", "main"])).toBe(
      "branch switch or discard uncommitted changes",
    );
  });

  it("does not match git commit", () => {
    expect(findMatch(["git", "commit", "-m", "test"])).toBeUndefined();
  });
});

describe("git reset matcher", () => {
  it("matches git reset", () => {
    expect(findMatch(["git", "reset", "--hard", "HEAD~1"])).toBe(
      "undo commits or discard staged/unstaged changes",
    );
  });

  it("does not match git log", () => {
    expect(findMatch(["git", "log", "--oneline"])).toBeUndefined();
  });
});

describe("matchDangerousCommand", () => {
  it("returns description and pattern for dangerous commands", () => {
    const result = matchDangerousCommand(["sudo", "apt", "update"]);
    expect(result).toEqual({
      description: "superuser command",
      pattern: "sudo",
    });
  });

  it("returns undefined for safe commands", () => {
    expect(matchDangerousCommand(["echo", "hello"])).toBeUndefined();
  });

  it("returns first match when multiple could apply", () => {
    // sudo comes before dd in the matcher list
    const result = matchDangerousCommand(["sudo", "dd", "of=/dev/sda"]);
    expect(result?.pattern).toBe("sudo");
  });
});

describe("shell wrappers, bypasses, literal variables, and heredocs", () => {
  const descriptions = (cmd: string) =>
    collectSimpleCommandMatches(cmd).map((m) => m.description);

  it("matches wrapped and escaped dangerous commands", () => {
    const cases: [string, string][] = [
      ["/bin/rm -rf x", "recursive force delete"],
      ["eval 'rm -rf x'", "recursive force delete"],
      ["bash -lc 'rm -rf x'", "recursive force delete"],
      ["zsh -c 'sudo ls'", "superuser command"],
      ["$'\x72m' -rf x", "recursive force delete"],
      ["nice -n 5 rm -rf x", "recursive force delete"],
      ["timeout -s KILL 5 rm -rf x", "recursive force delete"],
      ["env -u A rm -rf x", "recursive force delete"],
      ["env -S 'rm -rf x'", "recursive force delete"],
      ["echo x | xargs -n 1 rm -rf", "recursive force delete"],
      ["find . -delete", "find -delete"],
      ["find . -execdir rm {} +", "find -delete"],
      ["find . -exec sudo ls {} ;", "superuser command"],
      [
        "git -C repo reset --hard",
        "undo commits or discard staged/unstaged changes",
      ],
      ["git -c a=b push --force", "git force push"],
      ["git --git-dir=x clean -fd", "git clean (deletes untracked files)"],
      [`rm\${IFS}-rf x`, "recursive force delete"],
      ["{rm,-rf,x}", "recursive force delete"],
      ["curl x | /bin/bash", "download piped into a shell"],
      ["watch rm -rf x", "runs code that mentions a dangerous command"],
      ["$cmd -rf x", "command name comes from a variable"],
    ];
    for (const [command, expected] of cases) {
      expect(descriptions(command)).toContain(expected);
    }
  });

  it("resolves top-level literal variable assignments and ignores data heredocs", () => {
    const chrome =
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    expect(
      descriptions(
        `CH="${chrome}"; "$CH" --headless=new --screenshot=/tmp/a.png file://$PWD/a.html`,
      ),
    ).toEqual([]);
    expect(descriptions("X=rm; $X -rf /")).toContain("recursive force delete");
    expect(descriptions("X=sudo; $X ls")).toContain("superuser command");
    expect(
      descriptions(`python3 - <<'E'\nprint('$f',a==b,len(a))\nx = \${z}\nE`),
    ).toEqual([]);
    expect(descriptions("bash <<'E'\nrm -rf /\nE")).toContain(
      "recursive force delete",
    );
    expect(
      descriptions(
        `S=/Volumes/DabbleFiles/tmp/engruv-canary.e3keat; set -o pipefail; { tar -C "$S/flamingo-image.CB1i23" -cf - Dockerfile musicflamingo.py | ssh -o BatchMode=yes bigkahuna@192.168.1.52 'docker build --pull=false -t candidate - && docker run --rm --network=none --entrypoint python3 candidate -c "print(1)"'; }`,
      ),
    ).toEqual([]);
    expect(
      descriptions(
        'S=/Volumes/DabbleFiles/tmp/engruv-canary.e3keat; C=/Volumes/DabbleFiles/src/crater; W=/Users/ssweens/Spaces/crater/crater; D=$S/batch-ten-complete.836lo0mr; P=$C/.venv/bin/python; M=$C/data/v9_assets/hf_package; set -o pipefail; (env TMPDIR="$S/tmp" "$P" -B -u "$S/build-v5-batch-vocab.py" && cd "$W" && env TMPDIR="$S/tmp" "$P" -B -X faulthandler -u "$S/query-batch-v5-fusion.py") 2>&1 | tee "$S/query-batch-v5-fusion.log"',
      ),
    ).toEqual([]);
    expect(
      descriptions(
        'SCR=$(cat /tmp/chonk-v9-scratch-path); BASE=/Volumes/DabbleFiles/tmp/engruv-canary.e3keat/batch-ten-complete.836lo0mr; PY=/Volumes/DabbleFiles/src/crater/.venv/bin/python; export PYTHONPATH=/Users/ssweens/Spaces/crater/crater; { echo "scratch=$SCR"; "$PY" bin/build_v9_track_vectors.py --vectors-dir "$BASE/v9_vectors" --out "$SCR/baseline"; "$PY" "$SCR/build_v9_track_vectors_bounded.py" --vectors-dir "$BASE/v9_vectors" --out "$SCR/bounded"; } > "$SCR/build.log" 2>&1',
      ),
    ).toEqual([]);
    expect(
      descriptions(
        `set -eu; Q=$(cat /Users/ssweens/Spaces/.sessions/thr/queue-release-root.txt); cd "$Q"; P=/Volumes/DabbleFiles/src/engruv/.venv/bin/python; "$P" -B - <<'PY'\nfrom pathlib import Path\np=Path('bin/updatedata/pipeline_progress.py');s=p.read_text().replace('self.dismissed = 0','self.logged_skips: set[str] = set()',1).replace('.clear()','')\nPY`,
      ),
    ).toEqual([]);
    expect(
      descriptions(
        `P=/usr/bin/python3; "$P" "foo()" 'a & b' "function x" |& cat`,
      ),
    ).toEqual([]);
    expect(descriptions('export P=/usr/bin/python3; "$P" -V')).toEqual([]);
    expect(
      descriptions(
        '# don\'t break () &\nP=/usr/bin/python3 # inline () &\n"$P" -V',
      ),
    ).toEqual([]);
    expect(
      descriptions(
        'Q=$(if [ -f a ]; then echo 1; fi); P=/usr/bin/python3; "$P" -V',
      ),
    ).toEqual([]);
    expect(
      descriptions("P=/usr/bin/python3; \"$P\" -B - <<'PY'\n$X -rf /\nPY"),
    ).toEqual([]);
    expect(
      descriptions(
        'set -eu; A=/Users/ssweens/Spaces/.sessions/thr_mfyf295w9eb5; D=$(cat "$A/panel-022-proof-root.txt"); P=/Volumes/DabbleFiles/src/engruv/.venv/bin/python; for N in 80 120; do for TYPE in panel active; do "$P" -B "$A/render-tui-terminal-capture.py"; done; done',
      ),
    ).toEqual([]);
    expect(
      descriptions(
        `set -eu; A=/Users/ssweens/Spaces/.sessions/thr_mfyf295w9eb5; cd "$(cat "$A/audio-release-root.txt")"; P=/Volumes/DabbleFiles/src/engruv/.venv/bin/python; "$P" -B - <<'PY'\nfrom pathlib import Path\nprint(Path('a').read_text())\nPY\n"$P" -B -m pytest -q tests/test_pipeline_queue.py`,
      ),
    ).toEqual([]);
    expect(
      descriptions(
        '(umask 077; if [[ -z "$f" || "$f" -lt 55 ]]; then echo ok; fi)',
      ),
    ).toEqual([]);
    expect(
      descriptions("S=/tmp/x; (set -C; cat > \"$S/a.py\" <<'PY'\n$X -rf /\nPY\n)"),
    ).toEqual([]);
    expect(descriptions("X=echo; export X=rm; $X -rf /")).toContain(
      "recursive force delete",
    );
    expect(descriptions("S=/bin/sh; \"$S\" -c 'rm -rf /'")).toContain(
      "recursive force delete",
    );
    expect(descriptions("S=eval; \"$S\" 'rm -rf /'")).toContain(
      "recursive force delete",
    );
    for (const c of [
      "X=echo; IFS=c; $X -rf x",
      "f() { X=rm; }; X=echo; f; $X -rf x",
      "f () { X=rm; }; X=echo; f; $X -rf x",
      "function f { X=rm; }; X=echo; f; $X -rf x",
      "() { X=rm; }; X=echo; $X -rf x",
      "X=rm &\n$X -rf x",
      "X=echo; export X=$Y; $X -rf x",
      "P=/bin/bash; \"$P\" <<'E'\n$X foo\nE",
      'P=/usr/bin/python3; "$P" - <<PY\n$($X foo)\nPY',
    ]) {
      expect(descriptions(c), c).toContain(
        "command name comes from a variable",
      );
    }
  });
});

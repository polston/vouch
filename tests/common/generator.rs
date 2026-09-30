//! Automated grammar-driven synthetic command generator.
//!
//! Generates structural permutations of shell commands (bash, powershell, awk),
//! interpreter snippets (python, node, awk), and harness tool payloads.
//! Uses strictly neutral dummy data (/tmp/..., C:/work/..., C:/Users/dev, example.com)
//! with zero host-coupling, machine context, or developer privacy liabilities.

#![allow(dead_code)]

/// Deterministic Pseudo-Random Number Generator based on XorShift64.
/// 100% reproducible across platforms without external dependencies.
#[derive(Debug, Clone)]
pub struct GrammarRng {
    state: u64,
}

impl GrammarRng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x853c49e6748fea9b
            } else {
                seed
            },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + (self.next_u64() as usize % (max - min))
    }

    pub fn choose<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        assert!(!slice.is_empty(), "cannot choose from empty slice");
        &slice[self.next_range(0, slice.len())]
    }

    pub fn coin_flip(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }
}

pub struct SyntheticGenerator {
    rng: GrammarRng,
}

impl SyntheticGenerator {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: GrammarRng::new(seed),
        }
    }

    pub fn generate_batch(&mut self, count: usize) -> Vec<GeneratedCommand> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.generate_one());
        }
        out
    }

    pub fn generate_one(&mut self) -> GeneratedCommand {
        let kind = self.rng.next_range(0, 10);
        match kind {
            0 => self.generate_simple_unix(),
            1 => self.generate_git_command(),
            2 => self.generate_destructive_guard(),
            3 => self.generate_python_snippet(),
            4 => self.generate_node_snippet(),
            5 => self.generate_awk_snippet(),
            6 => self.generate_pipeline_or_sequence(),
            7 => self.generate_compound_loop(),
            8 => self.generate_redirect_write(),
            _ => self.generate_option_permutations(),
        }
    }

    fn generate_simple_unix(&mut self) -> GeneratedCommand {
        let heads = ["ls", "pwd", "date", "whoami", "uname", "cat", "head", "tail", "wc", "sort"];
        let head = self.rng.choose(&heads);
        let path = self.neutral_read_path();
        let cmd = match *head {
            "ls" => {
                let flag = self.rng.choose(&["-la", "-lh", "-l", "-a", ""]);
                if flag.is_empty() {
                    format!("ls {path}")
                } else {
                    format!("ls {flag} {path}")
                }
            }
            "pwd" | "date" | "whoami" => head.to_string(),
            "uname" => {
                let flag = self.rng.choose(&["-a", "-s", "-r", ""]);
                if flag.is_empty() {
                    "uname".to_string()
                } else {
                    format!("uname {flag}")
                }
            }
            "cat" | "wc" => {
                let flag = if *head == "wc" {
                    self.rng.choose(&["-l", "-w", "-c", ""])
                } else {
                    ""
                };
                if flag.is_empty() {
                    format!("{head} {path}")
                } else {
                    format!("{head} {flag} {path}")
                }
            }
            "head" | "tail" => {
                let n = self.rng.next_range(5, 50);
                format!("{head} -n {n} {path}")
            }
            "sort" => {
                let flag = self.rng.choose(&["-r", "-u", "-n", ""]);
                if flag.is_empty() {
                    format!("sort {path}")
                } else {
                    format!("sort {flag} {path}")
                }
            }
            _ => format!("{head} {path}"),
        };
        GeneratedCommand {
            cmd,
            verdict: "allow".to_string(),
            cwd: Some(self.neutral_cwd().to_string()),
        }
    }

    fn generate_git_command(&mut self) -> GeneratedCommand {
        let op = self.rng.next_range(0, 7);
        let (cmd, verdict) = match op {
            0 => ("git status".to_string(), "allow"),
            1 => {
                let n = self.rng.next_range(1, 20);
                (format!("git log --oneline -{n}"), "allow")
            }
            2 => ("git diff --stat HEAD~1".to_string(), "allow"),
            3 => ("git branch -a".to_string(), "allow"),
            4 => {
                let branch = self.rng.choose(&["feature", "patch-1", "fix-bug"]);
                (format!("git checkout -b {branch}"), "allow")
            }
            5 => {
                let remote = self.rng.choose(&["origin", "upstream"]);
                let branch = self.rng.choose(&["main", "master"]);
                let force = self.rng.choose(&["--force", "-f", "'-f'", "'--force'", "\"-f\""]);
                (format!("git push {force} {remote} {branch}"), "ask")
            }
            _ => {
                let flag = self.rng.choose(&["--hard", "'-hard'", "'--hard'", "\"--hard\""]);
                (format!("git reset {flag} HEAD~1"), "ask")
            }
        };
        GeneratedCommand {
            cmd,
            verdict: verdict.to_string(),
            cwd: Some(self.neutral_cwd().to_string()),
        }
    }

    fn generate_destructive_guard(&mut self) -> GeneratedCommand {
        let op = self.rng.next_range(0, 4);
        let (cmd, verdict) = match op {
            0 => {
                let flag = self.rng.choose(&["-rf", "-fr", "-r -f", "'-r' '-f'", "'-rf'", "\"--recursive\" -f"]);
                let target = self.neutral_scratch_path();
                (format!("rm {flag} {target}"), "ask")
            }
            1 => {
                let signal = self.rng.choose(&["-9", "-KILL", "-TERM", ""]);
                let pid = self.rng.next_range(1000, 9999);
                if signal.is_empty() {
                    (format!("kill {pid}"), "ask")
                } else {
                    (format!("kill {signal} {pid}"), "ask")
                }
            }
            2 => {
                let mode = self.rng.choose(&["+x", "755", "777", "u+w"]);
                let target = self.neutral_scratch_path();
                (format!("chmod {mode} {target}"), "ask")
            }
            _ => {
                let host = self.rng.choose(&["example.com", "dev.internal", "192.0.2.1"]);
                (format!("ssh -l dev {host}"), "ask")
            }
        };
        GeneratedCommand {
            cmd,
            verdict: verdict.to_string(),
            cwd: Some(self.neutral_cwd().to_string()),
        }
    }

    fn generate_python_snippet(&mut self) -> GeneratedCommand {
        let py = self.rng.choose(&["python", "python3"]);
        let op = self.rng.next_range(0, 5);
        let (cmd, verdict) = match op {
            0 => (format!("{py} -c \"print(1 + 2)\""), "allow"),
            1 => (format!("{py} -c \"import sys; sys.stdout.write('clean\\n')\""), "allow"),
            2 => {
                let p = self.neutral_scratch_path();
                (format!("{py} -c \"open('{p}', 'w').write('data')\""), "allow")
            }
            3 => {
                let p = self.neutral_scratch_path();
                (format!("{py} -c \"import shutil; shutil.rmtree('{p}')\""), "ask")
            }
            _ => {
                let p = self.neutral_scratch_path();
                (format!("{py} - <<'EOF'\nimport shutil\nshutil.rmtree('{p}')\nEOF\n"), "ask")
            }
        };
        GeneratedCommand {
            cmd,
            verdict: verdict.to_string(),
            cwd: Some(self.neutral_cwd().to_string()),
        }
    }

    fn generate_node_snippet(&mut self) -> GeneratedCommand {
        let op = self.rng.next_range(0, 2);
        let (cmd, verdict) = match op {
            0 => ("node -e \"console.log(process.version)\"".to_string(), "allow"),
            _ => {
                let p = self.neutral_scratch_path();
                (format!("node -e \"require('fs').writeFileSync('{p}', 'data')\""), "allow")
            }
        };
        GeneratedCommand {
            cmd,
            verdict: verdict.to_string(),
            cwd: Some(self.neutral_cwd().to_string()),
        }
    }

    fn generate_awk_snippet(&mut self) -> GeneratedCommand {
        let op = self.rng.next_range(0, 2);
        let p = self.neutral_read_path();
        let (cmd, verdict) = match op {
            0 => (format!("awk '{{print $1}}' {p}"), "allow"),
            _ => (format!("awk 'BEGIN {{ system(\"ls\") }}'"), "ask"),
        };
        GeneratedCommand {
            cmd,
            verdict: verdict.to_string(),
            cwd: Some(self.neutral_cwd().to_string()),
        }
    }

    fn generate_pipeline_or_sequence(&mut self) -> GeneratedCommand {
        let op = self.rng.next_range(0, 4);
        let (cmd, verdict) = match op {
            0 => ("cat /tmp/notes.txt | grep -i test | wc -l".to_string(), "allow"),
            1 => ("cd /tmp && ls -la".to_string(), "allow"),
            2 => ("mkdir -p /tmp/scratch/sub && echo hi > /tmp/scratch/sub/f.txt".to_string(), "allow"),
            _ => ("cat /tmp/notes.txt | while read -r line; do echo \"$line\"; done".to_string(), "allow"),
        };
        GeneratedCommand {
            cmd,
            verdict: verdict.to_string(),
            cwd: Some(self.neutral_cwd().to_string()),
        }
    }

    fn generate_compound_loop(&mut self) -> GeneratedCommand {
        let op = self.rng.next_range(0, 3);
        let (cmd, verdict) = match op {
            0 => ("for f in /tmp/*.txt; do head -n 1 \"$f\"; done".to_string(), "allow"),
            1 => ("if [ -f /tmp/test.txt ]; then cat /tmp/test.txt; fi".to_string(), "allow"),
            _ => ("for f in /tmp/*.txt; do rm -rf \"$f\"; done".to_string(), "ask"),
        };
        GeneratedCommand {
            cmd,
            verdict: verdict.to_string(),
            cwd: Some(self.neutral_cwd().to_string()),
        }
    }

    fn generate_redirect_write(&mut self) -> GeneratedCommand {
        let p = self.neutral_scratch_path();
        let op = self.rng.next_range(0, 3);
        let (cmd, verdict) = match op {
            0 => (format!("echo 'hello world' > {p}"), "allow"),
            1 => (format!("printf '%s\\n' 1 2 3 >> {p}"), "allow"),
            _ => {
                let protected = "$HOME/.config/vouch/config.toml";
                (format!("echo 'tamper' > {protected}"), "ask")
            }
        };
        GeneratedCommand {
            cmd,
            verdict: verdict.to_string(),
            cwd: Some(self.neutral_cwd().to_string()),
        }
    }

    fn generate_option_permutations(&mut self) -> GeneratedCommand {
        let prog = self.rng.choose(&["grep", "curl", "find", "tar"]);
        let (cmd, verdict) = match *prog {
            "grep" => {
                let flags = self.rng.choose(&["-rn", "-rnI", "'-rn'", "\"-r\" -n", "--recursive --line-number"]);
                let p = self.neutral_read_path();
                (format!("grep {flags} pattern {p}"), "allow")
            }
            "curl" => {
                let out = self.neutral_scratch_path();
                let flag = self.rng.choose(&["-o", "--output"]);
                (format!("curl -sSL {flag} {out} https://example.com/asset.tar.gz"), "allow")
            }
            "find" => {
                let flag = self.rng.choose(&["-name '*.txt'", "-type f", "'-maxdepth' 2"]);
                (format!("find /tmp {flag}"), "allow")
            }
            _ => {
                let archive = self.neutral_scratch_path();
                (format!("tar -czf {archive} /tmp/data"), "allow")
            }
        };
        GeneratedCommand {
            cmd,
            verdict: verdict.to_string(),
            cwd: Some(self.neutral_cwd().to_string()),
        }
    }

    fn neutral_read_path(&mut self) -> &'static str {
        self.rng.choose(&[
            "/tmp/notes.txt",
            "/tmp/data.csv",
            "/tmp/readme.md",
            "C:/work/notes.txt",
            "C:/work/data.csv",
        ])
    }

    fn neutral_scratch_path(&mut self) -> &'static str {
        self.rng.choose(&[
            "/tmp/scratch/out.txt",
            "/tmp/build/target",
            "/tmp/run/cache.bin",
            "C:/work/scratch/out.txt",
            "C:/work/build/target",
        ])
    }

    fn neutral_cwd(&mut self) -> &'static str {
        self.rng.choose(&[
            "/tmp",
            "/tmp/scratch",
            "C:/Users/dev",
            "C:/Users/dev/workspace",
            "C:/work",
        ])
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeneratedCommand {
    pub cmd: String,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

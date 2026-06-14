/**
 * bash-deny benchmark — engine vs CLI (tsx) vs CLI (compiled)
 *
 * Usage: node --import tsx scripts/bench.ts
 *
 * Build compiled version first: npx esbuild bash-deny/cli.ts --bundle --platform=node --outfile=dist/cli.mjs
 */

import { checkCommand, parseLine } from "../bash-deny/engine";
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// ── Short ruleset (4 rules from .pi/.bashdeny) ──────────────────

const shortRules = [
  parseLine("kubectl"),
  parseLine("! kubectl logs"),
  parseLine("git push --force"),
  parseLine("rm -rf"),
];

// ── Command pool (~200 commands: 60% allowed, 40% denied) ──────

const allowedCmds = [
  // kubectl logs (exception overrides kubectl rule)
  "kubectl logs nginx",
  "kubectl logs -f app",
  "kubectl logs --tail=100 pod",
  "kubectl logs --since=1h deployment/app",
  "kubectl logs -l app=nginx --all-containers",
  // git without --force
  "git push origin main",
  "git push --set-upstream origin feature",
  "git log --oneline",
  "git log --graph --all",
  "git status",
  "git diff HEAD~1",
  "git branch -a",
  "git checkout main",
  "git checkout -b new-branch",
  "git stash list",
  "git stash pop",
  "git remote -v",
  "git tag -l",
  "git rebase main",
  "git fetch origin",
  "git merge feature",
  // harmless commands
  "echo hello",
  "echo done",
  "echo \"processing...\"",
  "ls -la",
  "ls /tmp",
  "ls -lh /var/log",
  "cat README.md",
  "cat file.txt",
  "cat /etc/hostname",
  "grep -r pattern src/",
  "grep TODO *.ts",
  "grep -i error *.log",
  "find . -name '*.ts'",
  "find src -type f",
  "find /tmp -mtime -1",
  "docker ps",
  "docker images",
  "docker logs nginx",
  "docker inspect container",
  "npm install",
  "npm test",
  "npm run build",
  "npm audit",
  "npm ci",
  "curl -s localhost:3000",
  "curl --head example.com",
  "curl -X GET https://api.example.com/users",
  "wget https://example.com",
  "wget -q -O - https://example.com",
  "tar -czf archive.tar.gz src/",
  "tar -xzf archive.tar.gz",
  "unzip archive.zip",
  "head -20 file.txt",
  "head -100 /var/log/system.log",
  "tail -f log.txt",
  "tail -50 access.log",
  "wc -l *.ts",
  "wc -c file.txt",
  "sort data.txt",
  "sort -n numbers.txt",
  "uniq items.txt",
  "date",
  "date -u",
  "whoami",
  "pwd",
  "hostname",
  "uptime",
  "df -h",
  "du -sh src/",
  "du -h --max-depth=1",
  "mkdir -p /tmp/test",
  "touch newfile.txt",
  "cp a.txt b.txt",
  "cp -r src/ backup/",
  "mv old.txt new.txt",
  "less README.md",
  "file *.ts",
  "ssh -V",
  "ssh -T git@github.com",
  "which node",
  "type bash",
  "env",
  "printenv PATH",
  "man ls",
  "basename /path/to/file",
  "dirname /path/to/file",
  "cut -d, -f1 data.csv",
  "tr a-z A-Z < input.txt",
  // rm without -rf
  "rm single-file.txt",
  "rm -i dangerous.txt",
  "rm -r empty-dir/",
  "rm --preserve-root file",
  // chained safe commands
  "echo one && echo two",
  "ls && pwd",
  "cat file && wc -l file",
  "date && uptime",
  // safe wrappers
  "sudo echo hello",
  "sudo ls /root",
  "sudo whoami",
  "nohup npm start &",
  "env FOO=bar echo safe",
  "time ls -la",
  "nice -n 10 npm test",
];

const deniedCmds = [
  // kubectl (blocked by bare "kubectl" rule)
  "kubectl delete pod",
  "kubectl delete deployment app",
  "kubectl delete service nginx",
  "kubectl delete --all pods",
  "kubectl get pods",
  "kubectl get nodes -o wide",
  "kubectl describe nginx",
  "kubectl describe node worker-1",
  "kubectl exec -it pod -- sh",
  "kubectl exec deploy/nginx -- date",
  "kubectl apply -f config.yaml",
  "kubectl apply -k overlays/prod",
  "kubectl rollout restart deployment/app",
  "kubectl rollout undo deployment/app",
  "kubectl scale --replicas=3 deployment/app",
  "kubectl patch deployment app -p '{\"spec\":{\"replicas\":3}}'",
  "kubectl create namespace test",
  "kubectl create secret generic api-key --from-literal=key=secret",
  "kubectl drain node-1",
  "kubectl drain node-1 --delete-emptydir-data",
  "kubectl cordon node-1",
  "kubectl taint nodes node-1 key=value:NoSchedule",
  "kubectl run nginx --image=nginx",
  "kubectl port-forward svc/app 8080:80",
  "kubectl top pods",
  "kubectl cluster-info dump",
  // git push --force
  "git push --force origin main",
  "git -C /repo push --force origin main",
  "git push --force-with-lease origin feature",
  "git push origin +main",
  "git -C ~/project push --force --no-verify origin HEAD",
  // rm -rf
  "rm -rf /tmp/foo",
  "rm -rf /var/log/old",
  "rm -rf node_modules",
  "rm -rf dist/",
  "rm -rf .cache/",
  "rm -rf ~/Downloads/old",
  "rm -rf /tmp/*.log",
  "rm -rf --no-preserve-root /",
  // rm -rf with various flag orders
  "rm -fr /tmp/thing",
  "rm -Rf /tmp/cache",
  // wrapped denies
  "sudo kubectl delete pod",
  "sudo kubectl apply -f /etc/kubernetes/admin.yaml",
  "sudo rm -rf /tmp/cache",
  "sudo rm -rf /usr/local/old",
  "sudo git -C /repo push --force origin main",
  "env FOO=bar rm -rf /tmp/thing",
  "nohup rm -rf /tmp/large &",
  "su -c \"rm -rf /tmp/danger\"",
  "bash -c \"kubectl delete pod\"",
  "bash -c \"rm -rf /opt/old\"",
  "sh -c \"git push --force origin main\"",
  "zsh -c \"kubectl delete namespace test\"",
  // chained denies
  "kubectl delete pod || echo failed",
  "echo setup && kubectl delete pod",
  "git status && git push --force origin main",
  "echo begin && rm -rf /tmp/cache && echo end",
  // multi-segment
  "echo safe && rm -rf /tmp/cache || echo done",
  "kubectl describe pod ; echo second",
  // sudo chained wrappers
  "sudo nice -n -5 rm -rf /tmp/foo",
  "sudo -u root rm -rf /etc/config",
  "sudo -u root bash -c \"rm -rf /home/*/.cache\"",
  "sudo -E kubectl delete pod",
  "sudo nice -n 10 kubectl delete pod",
  "sudo env FOO=bar rm -rf /tmp/danger",
  // more wrapped
  "watch -n1 kubectl delete pod",
  "nohup kubectl apply -f destroy.yaml &",
  "chroot /newroot rm -rf /",
  "flock /tmp/lock rm -rf /tmp/shared",
];

function buildPool(size: number): string[] {
  const allowed = allowedCmds.slice(0, Math.ceil(size * 0.6));
  const denied = deniedCmds.slice(0, Math.floor(size * 0.4));
  const pool = [...allowed, ...denied];

  // Shuffle deterministically
  let seed = 42;
  const random = () => { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; };
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  return pool;
}

const pool = buildPool(200);

// ── Benchmarks ────────────────────────────────────────────────────

function engineBench(
  patterns: ReturnType<typeof parseLine>[],
  label: string,
  iterations: number,
) {
  // Warmup
  for (const cmd of pool) checkCommand(cmd, patterns);

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    checkCommand(pool[i % pool.length], patterns);
  }
  const elapsedMs = performance.now() - start;

  const opsPerSec = Math.round((iterations / elapsedMs) * 1000);
  const avgUs = ((elapsedMs / iterations) * 1000).toFixed(1);
  console.log(`  ${label.padEnd(16)} │ ${String(opsPerSec).padStart(8)} │ ${avgUs.padStart(8)}`);
}

function cliBench(label: string, cliPath: string, iterations: number) {
  const tmpDir = mkdtempSync(join(tmpdir(), "bash-deny-bench-"));
  const rulesPath = join(tmpDir, "rules.bashdeny");
  writeFileSync(rulesPath, "kubectl\n! kubectl logs\ngit push --force\nrm -rf\n");

  // Warmup
  for (let i = 0; i < 3; i++) {
    spawnSync(`${cliPath} -f "${rulesPath}" -q -i "echo hello"`, {
      shell: true, stdio: "ignore", timeout: 5000,
    });
  }

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    const cmd = pool[i % pool.length];
    spawnSync(`${cliPath} -f "${rulesPath}" -q -i "${cmd}"`, {
      shell: true, stdio: "ignore", timeout: 5000,
    });
  }
  const elapsedMs = performance.now() - start;

  rmSync(tmpDir, { recursive: true, force: true });

  const opsPerSec = Math.round((iterations / elapsedMs) * 1000);
  const avgMs = (elapsedMs / iterations).toFixed(1);
  console.log(`  ${label.padEnd(16)} │ ${String(opsPerSec).padStart(8)} │ ${(avgMs + "ms").padStart(8)}`);
}

// ── Main ──────────────────────────────────────────────────────────

console.log("╔══════════════════════════════════════════════╗");
console.log("║           bash-deny benchmark               ║");
console.log("╠══════════════════════════════════════════════╣");
console.log("║ Scenario         │ ops/sec  │ avg time      ║");
console.log("╠══════════════════════════════════════════════╣");

engineBench(shortRules, `engine (${shortRules.length})`, 10_000);
cliBench("CLI (tsx)", "node --import tsx bash-deny/cli.ts", 100);
cliBench("CLI (cjs+minify)", "node dist/cli.cjs.min.mjs", 100);
cliBench("CLI (bun ts)", "bun run bash-deny/cli.ts", 100);
cliBench("CLI (bun binary)", "dist/bash-deny-bun", 100);

console.log("╚══════════════════════════════════════════════╝");
console.log(`\nPool: ${pool.length} commands`);
console.log(`Engine: 10,000 iterations  |  CLI: 100 iterations each`);

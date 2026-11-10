# run-container.ps1 - start the Agent Trap Lab container (Windows PowerShell)
#
#   DeepSeek target : uses an API key (pass -DeepseekKey, or an -EnvFile with DEEPSEEK_API_KEY)
#   Claude   target : uses subscription login (claude login inside the container,
#                     credentials persisted in the named volume trap-claude-auth)
#
# Build first (tag must match the default below, or pass -Image):
#   docker build -t trap-lab:v16 .
#
# Usage:
#   .\run-container.ps1 -DeepseekKey sk-xxxxxxxx
#   .\run-container.ps1 -EnvFile E:\secrets\trap-lab.env
#   .\run-container.ps1 -Image trap-lab:v16 -Name trap-lab -DeepseekKey sk-xxxxxxxx
#
# If PowerShell blocks the script (ExecutionPolicy), run it like this:
#   powershell -ExecutionPolicy Bypass -File .\run-container.ps1 -DeepseekKey sk-xxxxxxxx
#
# First time only - log Claude in once (reused afterwards via the named volume):
#   claude            # pick "Claude account (Pro/Max)", open the URL, paste the code back
#   claude -p "hi"    # verify it works
# The container runs as root (runner needs root to drop the target agent to the sandbox user).
# Login lives in /root/.claude; the named volume below persists it across container recreations.
#
# Then run experiments, e.g.:
#   python3 runner/preflight.py
#   python3 runner/run.py selftest
#   python3 runner/run.py all --agent deepseek --scenarios A1v,A1vp --profiles yolo --repeats 5 --interleave --tag v16
#   python3 runner/run.py all --agent claude   --scenarios A1v,A1vp,A4 --profiles yolo --repeats 8 --interleave --tag v16

param(
  [string]$Image       = "trap-lab:v16",
  [string]$Name        = "trap-lab",
  [string]$DeepseekKey = "",
  [string]$EnvFile     = ""
)

# Remove any existing container with the same name, so re-running this acts like an in-place replace.
# This does NOT touch the trap-claude-auth volume or the results folder - login and results are kept.
docker rm -f $Name 2>$null | Out-Null

# Build the DeepSeek key argument: inline -e if a key was passed, else --env-file if it exists.
$keyArgs = @()
if ($DeepseekKey -ne "") {
  $keyArgs = @("-e", "DEEPSEEK_API_KEY=$DeepseekKey")
} elseif ($EnvFile -ne "" -and (Test-Path $EnvFile)) {
  $keyArgs = @("--env-file", $EnvFile)
} else {
  Write-Host "WARNING: no DeepSeek key given. Pass -DeepseekKey sk-xxxx or -EnvFile <path>." -ForegroundColor Yellow
  Write-Host "         Claude runs still work (named volume); DeepSeek runs will fail without the key."
}

# results -> host current dir (kept on exit); Claude login -> named volume (persisted, root).
docker run -it --name $Name `
  $keyArgs `
  -v "${PWD}\results:/lab/results" `
  -v "trap-claude-auth:/root/.claude" `
  $Image

# Notes:
# - No --rm: the container is kept after you exit, so you can resume it with:  docker start -ai $Name
#   Re-running this script force-removes it first and starts fresh from the image.
# - If the results mount fails with a permission error, drop that -v line and after the run use:
#       docker cp <container>:/lab/results ./results
# - Changed code? Rebuild the image (docker build -t trap-lab:v16 .) before running this again.

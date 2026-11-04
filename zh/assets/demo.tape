Output docs/assets/demo.gif

Require echo

Set Shell "zsh"
Set FontSize 14
Set Width 1200
Set Height 600
Set Padding 20
Set WindowBar Colorful
Set TypingSpeed 55ms
Set Theme "Dracula"

# ── Setup (hidden) ──────────────────────────────────────────────────────────
Hide
Type "alias pipguard='demo/pipguard-demo'"
Enter
Type "clear"
Enter
Show

# ── Version ─────────────────────────────────────────────────────────────────
Sleep 500ms
Type "pipguard --version"
Sleep 400ms
Enter
Sleep 1.5s

# ── Scene 1: Attack BLOCKED ─────────────────────────────────────────────────
Type "# Block the March 2026 litellm supply-chain attack"
Sleep 300ms
Enter
Sleep 400ms

Type "pipguard install litellm==1.82.8"
Sleep 400ms
Enter
Sleep 6s

Sleep 3s

# ── Scene 2: Clean install ──────────────────────────────────────────────────
Type "# Clean packages pass straight through"
Sleep 300ms
Enter
Sleep 400ms

Type "pipguard install requests"
Sleep 400ms
Enter
Sleep 5.5s

Sleep 1.5s

# ── Scene 3: CI mode with requirements.txt ──────────────────────────────────
Type "# CI mode — non-interactive, exits 1 on CRITICAL/HIGH"
Sleep 300ms
Enter
Sleep 400ms

Type "pipguard install --yes -r demo/requirements.txt"
Sleep 400ms
Enter
Sleep 6.5s

Sleep 3s

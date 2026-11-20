# Record a FoxByte branch being created.
# Requires a running engine and `fox` on PATH. See docs/assets/README.md.
# Run from the repository root: vhs docs/assets/demo.tape

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1100
Set Height 560
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms

Hide
Type "clear"
Enter
Show

Type "fox branch create demo"
Sleep 400ms
Enter
Sleep 5s

Type "fox sql --branch demo 'CREATE TABLE notes (id int primary key, body text);'"
Sleep 200ms
Enter
Sleep 3s

Type "fox blackbox demo"
Sleep 200ms
Enter
Sleep 4s

Type "fox branch delete demo"
Sleep 200ms
Enter
Sleep 3s

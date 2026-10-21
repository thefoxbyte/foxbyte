// The console's three typefaces, bundled into the build and served by the
// engine itself, so opening the console asks no other site for anything (it
// used to load them from Google Fonts). Same families and weights as before:
// Space Grotesk for display, Inter for body, JetBrains Mono for code. Each
// stylesheet carries every script's subset behind a unicode-range, so a page
// downloads only the subsets its text uses. SIL Open Font License 1.1; the
// licences ship at /licenses/fonts/.
import '@fontsource/space-grotesk/500.css'
import '@fontsource/space-grotesk/600.css'
import '@fontsource/space-grotesk/700.css'
import '@fontsource/inter/400.css'
import '@fontsource/inter/500.css'
import '@fontsource/inter/600.css'
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/500.css'
